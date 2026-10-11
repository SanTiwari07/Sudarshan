"""
REAL Frida, LOCAL Linux process - not Android.

These tests load the production agent bundle (frida_hooks/banking_trojan.bundle.js)
with frida 17 into a benign child Python process on the test host, and follow
what the agent sends through the real host pipeline:

    agent send() -> FridaSession._on_message -> collected_events
                 -> RuntimeEventBus -> EvidenceStore -> BFCI
                 -> TelemetryDiagnostics classification

What they prove, and what they do NOT:

  * They prove the bundle compiles and loads under frida 17.16.4, that the
    load canary and agent errors reach the host, that a real Interceptor hook
    firing in the target produces an event that survives every host stage,
    and that a session lost to process death is recorded with its reason.
  * The host has no ART, so the agent's Java bridge is unavailable here and
    no Java hook is exercised. The native hooks look up Android's `libc.so`;
    glibc calls it `libc.so.6`, so the test renames that one module string
    in a COPY of the bundle. Nothing here is a statement about behaviour on
    an Android device.

Skipped automatically when frida is not installed or the host forbids
attaching to a child process (e.g. Yama ptrace_scope, containers without
CAP_SYS_PTRACE).
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

frida = pytest.importorskip("frida")

from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2, explain_bfci
from sudarshan_core.engines.frida_sandbox import (
    FridaSession,
    _apply_agent_config,
    _select_hooks_script,
)
from sudarshan_core.engines.telemetry_diagnostics import TelemetryClassification

pytestmark = pytest.mark.frida_local

_CONNECTOR = """
import socket, time, sys
port = int(sys.argv[1])
while True:
    s = socket.socket()
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port))
    except OSError:
        pass
    finally:
        s.close()
    time.sleep(0.3)
"""

_SLEEPER = "import time\nwhile True:\n    time.sleep(1)\n"


def _agent_source(linux_libc: bool) -> str:
    bundle = _select_hooks_script()
    if not bundle.exists():
        pytest.skip("compiled agent bundle not present")
    src = bundle.read_text(encoding="utf-8")
    if linux_libc:
        # Test-only: point the native block at glibc. _apply_agent_config
        # re-computes the frida package header after the edit.
        src = src.replace('"libc.so"', '"libc.so.6"')
    return _apply_agent_config(src, "com.example.benign")


def _spawn_child(tmp_path: Path, code: str, *args: str) -> subprocess.Popen:
    script = tmp_path / "child.py"
    script.write_text(code, encoding="utf-8")
    proc = subprocess.Popen([sys.executable, "-I", str(script), *args])
    time.sleep(0.4)
    return proc


def _attach_or_skip(pid: int):
    try:
        return frida.attach(pid)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"host does not allow frida to attach to a child: {exc}")


def _session(tmp_path: Path) -> FridaSession:
    return FridaSession(
        device_serial="local-host",
        package_name="com.example.benign",
        artifact_dir=tmp_path,
        case_id="frida-local-test",
    )


def _wait_until(pred, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return pred()


def test_bundle_loads_and_reports_missing_java_bridge_honestly(tmp_path):
    """No ART on this host: the run must say AGENT_INIT_FAILED, not 'quiet sample'."""
    child = _spawn_child(tmp_path, _SLEEPER)
    fs = _session(tmp_path)
    try:
        fs._session = _attach_or_skip(child.pid)
        fs._load_primary_agent(_agent_source(linux_libc=False), child.pid)
        assert _wait_until(lambda: fs.canary_received and fs.java_bridge_failed)
        fs.telemetry.mark_window_end()
        report = fs.telemetry.to_dict(fs.event_bus.metrics(), fs.evidence_store.metrics())
        assert report["agent"]["loaded"] is True
        assert report["agent"]["canary_received"] is True
        assert report["agent"]["java_bridge_failed"] is True
        assert report["classification"] == TelemetryClassification.AGENT_INIT_FAILED.value
        assert report["events"]["received"] == 0
    finally:
        child.kill()
        child.wait(5)
        try:
            fs._session.detach()
        except Exception:
            pass
        fs.event_bus.close(2.0)


def test_native_hook_event_propagates_to_evidence_and_score(tmp_path):
    """A real connect() in the target becomes a persisted, cited, scored event."""
    child = _spawn_child(tmp_path, _CONNECTOR, "9")
    fs = _session(tmp_path)
    try:
        fs._session = _attach_or_skip(child.pid)
        fs._load_primary_agent(_agent_source(linux_libc=True), child.pid)
        assert _wait_until(lambda: len(fs.collected_events["network"]) >= 2), (
            f"no native network events; telemetry={fs.telemetry.to_dict()}"
        )
        fs.telemetry.mark_window_end()
        assert fs.event_bus.drain(5.0)

        tele = fs.telemetry.to_dict(fs.event_bus.metrics(), fs.evidence_store.metrics())
        assert tele["hooks"]["installed"] >= 1
        assert tele["events"]["received"] >= 2
        assert tele["events"]["published"] == tele["events"]["received"] - tele["events"]["filtered"]
        assert tele["processing_losses"]["handler_exceptions"] == 0
        assert tele["processing_losses"]["bus_dropped"] == 0
        assert tele["classification"] == TelemetryClassification.RUNTIME_EVENTS_RECEIVED.value
        assert tele["hooks"]["fire_counts"].get("libc.connect", 0) >= 2

        ev = fs.collected_events["network"][0]
        assert ev["hook"] == "libc.connect"
        assert ev["ioc"].startswith("127.0.0.1:")

        records = fs.evidence_store.get_all()
        native = [r for r in records if r.api == "libc.connect"]
        assert native, [r.api for r in records]
        assert all(r.provenance["source"] == "frida_native" for r in native)
        assert all(r.provenance["synthetic"] is False for r in native)
        assert all(r.provenance["case_id"] == "frida-local-test" for r in native)
        assert len({r.evidence_key for r in records}) == len(records)

        # The score that results cites these exact events.
        explained = explain_bfci(fs.collected_events)
        net = explained["contributions"]["network"]
        assert net["event_count"] >= 1
        assert net["contribution"] > 0
        # Every cited event is a persisted evidence record.
        stored_keys = {r.evidence_key for r in records}
        assert set(net["evidence_refs"]) <= stored_keys
        assert explained["bfci"] == calculate_bfci_v2(fs.collected_events)[0]
    finally:
        child.kill()
        child.wait(5)
        try:
            fs._session.detach()
        except Exception:
            pass
        fs.event_bus.close(2.0)


def test_process_death_is_recorded_as_lost_instrumentation(tmp_path):
    """Hooks installed, target dies mid-window, no events: never 'not exercised'."""
    child = _spawn_child(tmp_path, _SLEEPER)
    fs = _session(tmp_path)
    try:
        fs._session = _attach_or_skip(child.pid)
        fs._load_primary_agent(_agent_source(linux_libc=True), child.pid)
        assert _wait_until(lambda: fs.telemetry.hooks_installed > 0)
        child.kill()
        child.wait(5)
        assert _wait_until(lambda: fs.telemetry.detached), "detached signal not delivered"
        fs.telemetry.mark_window_end()
        report = fs.telemetry.to_dict()
        assert report["session"]["detach_reason"] == "process-terminated"
        assert report["session"]["attached_at_window_end"] is False
        assert report["events"]["received"] == 0
        # Java bridge is absent on this host, so AGENT_INIT_FAILED outranks the
        # detach; the point is that the result is NOT a clean "nothing happened".
        assert report["classification"] in (
            TelemetryClassification.AGENT_INIT_FAILED.value,
            TelemetryClassification.NO_TELEMETRY_OBSERVED.value,
        )
        assert report["classification"] != TelemetryClassification.HOOKS_INSTALLED_NOT_EXERCISED.value
    finally:
        if child.poll() is None:
            child.kill()
        fs.event_bus.close(2.0)


def test_agent_with_hostile_package_name_still_loads(tmp_path):
    child = _spawn_child(tmp_path, _SLEEPER)
    fs = _session(tmp_path)
    try:
        fs._session = _attach_or_skip(child.pid)
        src = _apply_agent_config(
            _select_hooks_script().read_text(encoding="utf-8"), 'com.evil"\n;bad()//',
        )
        fs._load_primary_agent(src, child.pid)
        assert _wait_until(lambda: fs.canary_received)
        assert not fs.telemetry.agent_load_error
        assert not fs.telemetry.script_errors
    finally:
        child.kill()
        child.wait(5)
        try:
            fs._session.detach()
        except Exception:
            pass
        fs.event_bus.close(2.0)
