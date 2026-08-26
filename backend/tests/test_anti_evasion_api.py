"""Autonomous anti-evasion endpoint: wiring, live progress, and mutual exclusion.

The sandbox provider is faked, so this exercises what the HTTP layer owns -
resolving the device, driving the sequence step by step, publishing each step
to the live stream, and refusing a second concurrent run on the same device -
without touching an emulator. The verdict logic itself is covered by
``tests/unit/test_anti_evasion.py``.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import List, Tuple

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")
os.environ.setdefault("SUDARSHAN_RATE_LIMIT_DISABLED", "true")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.auth.auth import require_analyst  # noqa: E402
from app.main import app  # noqa: E402
from app.routes import resilience, runtime_api  # noqa: E402
from app.services.resilience_events import hub  # noqa: E402

SESSION = "a" * 64
PACKAGE = "com.evil.dropper"


class FakeDevice:
    """Answers every dump the sequence reads; records what it was asked."""

    def __init__(self) -> None:
        self.commands: List[str] = []
        self.epoch = 1_760_000_000
        self.serial = "emulator-5554"

    # ── SandboxProvider surface used by the route and the orchestrator ────

    def select_device(self, preferred_serial=None):
        return self

    def check_root(self, serial: str) -> bool:
        return True

    def adb_shell(self, serial: str, command: str, timeout: int = 30) -> Tuple[bool, str]:
        self.commands.append(command)
        if command.startswith("getprop"):
            return True, "33"
        if command == "date +%s":
            return True, str(self.epoch)
        if command.startswith("date "):
            # Accepted and applied, so the warp verifies; the exact format is
            # the time-warp engine's business, not this test's.
            self.epoch += 6 * 3600
            return True, ""
        if command == "dumpsys battery":
            return True, "  AC powered: false\n  status: 3\n  level: 50\n"
        if command == "dumpsys window windows":
            return True, "  Window #0 Window{aaaa u0 StatusBar}:\n    ty=STATUS_BAR\n"
        if command == "dumpsys accessibility":
            return True, "User state[attributes:0]\n     Bound services:{}\n"
        if command.startswith("settings get secure"):
            return True, "null"
        if command.startswith("cmd package list packages -U"):
            return True, f"package:{PACKAGE} uid:10188"
        if command.startswith("cat /proc/net/tcp"):
            return True, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
        if "content query" in command:
            return True, "\n".join(f"Row: {i} _id={i + 1}" for i in range(12))
        if "content insert" in command:
            return True, "__OK__\n" * command.count("__OK__")
        return True, ""


@pytest.fixture
def sandbox(monkeypatch):
    device = FakeDevice()
    import sudarshan_core.sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "get_sandbox_provider", lambda *a, **k: device)
    app.dependency_overrides[require_analyst] = lambda: {
        "username": "tester",
        "role": "analyst",
    }
    hub._history.clear()
    resilience._anti_evasion_locks.clear()
    yield device
    app.dependency_overrides.pop(require_analyst, None)


def _post(body):
    async def _call():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.post(
                f"/api/v1/analysis/{SESSION}/autonomous-anti-evasion", json=body
            )

    return asyncio.run(_call())


def test_sequence_runs_every_step_and_reports_the_delta(sandbox):
    resp = _post(
        {
            "package_name": PACKAGE,
            "observation_seconds": 0,
            "contact_count": 12,
            "sms_count": 4,
        }
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()

    keys = [s["key"] for s in payload["steps"]]
    assert keys == [
        "warp_6h", "warp_12h", "warp_24h",
        "battery", "contacts", "calls", "sms", "photos",
        "observe",
    ]
    assert payload["device_serial"] == "emulator-5554"
    assert payload["package_name"] == PACKAGE

    # No tracker reports Frida running, so the hook metrics were never
    # observable and the endpoint must not return a clean bill of health.
    assert payload["verdict"] == "NO_RUNTIME_TELEMETRY"
    by_key = {d["key"]: d for d in payload["deltas"]}
    assert by_key["sms_reads"]["delta"] is None
    assert by_key["sms_reads"]["observable"] is False
    # Device-side observation still happened.
    assert by_key["overlay_windows"]["before"] == 0

    # The card reads these directly - clock ends, battery, rows written.
    applied = payload["applied_changes"]
    assert applied["clock_shift_hours"] == pytest.approx(24, abs=0.1)
    assert applied["clock_after_ms"] > applied["clock_before_ms"] > 0
    assert applied["battery_level"] == 50
    assert applied["doze_cycled"] is True

    # The device really was driven, not just described.
    assert "dumpsys deviceidle force-idle" in sandbox.commands
    assert "dumpsys deviceidle unforce" in sandbox.commands
    assert any(c.startswith("dumpsys battery set level 50") for c in sandbox.commands)


def test_each_step_is_published_to_the_live_stream(sandbox):
    _post({"package_name": PACKAGE, "observation_seconds": 0})

    events = hub.history(SESSION)
    steps = [e for e in events if e["event"] == "ANTI_EVASION_STEP"]
    complete = [e for e in events if e["event"] == "ANTI_EVASION_COMPLETE"]

    assert steps[0]["payload"]["phase"] == "started"
    # The whole plan is announced up front so the panel can show what is left.
    assert [s["key"] for s in steps[0]["payload"]["steps"]][0] == "warp_6h"
    assert {e["payload"]["phase"] for e in steps[1:]} == {"running", "finished"}
    assert len(complete) == 1
    assert complete[0]["payload"]["verdict"] == "NO_RUNTIME_TELEMETRY"


def test_a_second_sequence_on_the_same_device_is_refused(sandbox):
    async def _call():
        lock = asyncio.Lock()
        await lock.acquire()
        resilience._anti_evasion_locks["emulator-5554"] = lock
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.post(
                f"/api/v1/analysis/{SESSION}/autonomous-anti-evasion",
                json={"package_name": PACKAGE, "observation_seconds": 0},
            )

    resp = asyncio.run(_call())
    assert resp.status_code == 409
    assert "already running" in resp.json()["detail"]


def test_no_sandbox_available_is_a_503_not_a_verdict(monkeypatch):
    """A missing device must never read as "nothing happened"."""
    import sudarshan_core.sandbox as sandbox_module

    def _explode(*_a, **_k):
        raise RuntimeError("no devices")

    monkeypatch.setattr(sandbox_module, "get_sandbox_provider", _explode)
    app.dependency_overrides[require_analyst] = lambda: {"username": "t", "role": "analyst"}
    try:
        resp = _post({"package_name": PACKAGE, "observation_seconds": 0})
    finally:
        app.dependency_overrides.pop(require_analyst, None)
    assert resp.status_code == 503


# ── Hook telemetry probe ───────────────────────────────────────────────────


class FakeTracker:
    def __init__(self, package_name: str, frida_running: bool):
        self.package_name = package_name
        self.case_id = package_name
        self.frida_running = frida_running
        self.attached = frida_running


def test_telemetry_counts_are_monotonic_across_ring_buffer_eviction(monkeypatch):
    """
    Category totals must not be derived from the bounded event buffer.

    A delta computed from a ring that has wrapped would report a *drop* where
    events were merely evicted, which is the one arithmetic error this feature
    cannot survive.
    """
    monkeypatch.setattr(runtime_api, "_category_totals", {})
    monkeypatch.setattr(runtime_api, "_recent_events", [])
    monkeypatch.setattr(runtime_api, "_MAX_RECENT_EVENTS", 3)

    for _ in range(10):
        runtime_api.record_event({"category": "sms", "type": "FRIDA_EVENT"})

    assert len(runtime_api._recent_events) == 3
    assert runtime_api.hook_telemetry_snapshot()["counts"]["sms"] == 10


def test_attachment_is_judged_per_package(monkeypatch):
    monkeypatch.setattr(
        runtime_api,
        "_ACTIVE_TRACKERS",
        {"other": FakeTracker("com.other.app", True)},
    )
    assert runtime_api.hook_telemetry_snapshot(PACKAGE)["attached"] is False
    assert runtime_api.hook_telemetry_snapshot("com.other.app")["attached"] is True


def test_a_tracker_with_no_frida_is_not_an_attached_stream(monkeypatch):
    monkeypatch.setattr(
        runtime_api,
        "_ACTIVE_TRACKERS",
        {PACKAGE: FakeTracker(PACKAGE, False)},
    )
    snapshot = runtime_api.hook_telemetry_snapshot(PACKAGE)
    assert snapshot["attached"] is False
    assert snapshot["concurrent_sessions"] == 0
