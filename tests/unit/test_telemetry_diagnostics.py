"""
Telemetry pipeline classification and the hardened Frida message handler.

All MOCKED: no frida, no device. The real-Frida counterpart is
tests/integration/test_frida_local_agent.py.
"""

from __future__ import annotations

import threading

import pytest

from sudarshan_core.engines.frida_sandbox import FridaSession, _finalize_session_telemetry
from sudarshan_core.engines.telemetry_diagnostics import (
    TelemetryClassification as C,
    TelemetryDiagnostics,
)


def _loaded(hooks: int = 5) -> TelemetryDiagnostics:
    t = TelemetryDiagnostics("case-1", "com.example")
    t.record_attach(1234)
    t.record_agent_loaded()
    t.record_canary()
    for i in range(hooks):
        t.record_hook_installed(i + 1)
    return t


def _event_message(hook: str = "SmsManager.sendTextMessage", category: str = "sms", eid: str = "ev_1"):
    return {
        "type": "send",
        "payload": {
            "type": "event",
            "payload": {
                "event_id": eid, "timestamp": 1_700_000_000_000, "category": category,
                "hook": hook, "source": "frida", "data": {"hook": hook, "description": "x"},
            },
        },
    }


# ── Classification ladder ────────────────────────────────────────────────────

def test_never_attached_is_attach_failure():
    t = TelemetryDiagnostics()
    t.record_attach_failed("ProcessNotFoundError")
    assert t.classify() is C.FRIDA_ATTACH_FAILED
    assert t.to_dict()["attach"]["error"] == "ProcessNotFoundError"


def test_load_error_is_agent_init_failure():
    t = TelemetryDiagnostics()
    t.record_attach(1)
    t.record_agent_load_failed("InvalidArgumentError: script(line 1): SyntaxError")
    assert t.classify() is C.AGENT_INIT_FAILED


def test_loaded_without_canary_is_agent_init_failure():
    t = TelemetryDiagnostics()
    t.record_attach(1)
    t.record_agent_loaded()
    assert t.classify() is C.AGENT_INIT_FAILED


def test_java_bridge_failure_is_agent_init_failure():
    t = _loaded()
    t.record_agent_error("Java bridge unavailable", java_bridge_failed=True)
    t.mark_window_end()
    assert t.classify() is C.AGENT_INIT_FAILED


def test_zero_hooks_is_hook_install_failure():
    t = _loaded(hooks=0)
    t.mark_window_end()
    assert t.classify() is C.HOOK_INSTALL_FAILED


def test_hooks_live_for_whole_window_is_not_exercised():
    t = _loaded()
    t.mark_window_end()
    assert t.classify() is C.HOOKS_INSTALLED_NOT_EXERCISED


def test_detach_before_window_end_is_no_telemetry_not_quiet_sample():
    t = _loaded()
    t.record_detached("process-terminated")
    t.mark_window_end()
    d = t.to_dict()
    assert d["classification"] == C.NO_TELEMETRY_OBSERVED.value
    assert d["session"]["attached_at_window_end"] is False
    assert d["session"]["detach_reason"] == "process-terminated"


def test_window_never_closed_is_no_telemetry():
    assert _loaded().classify() is C.NO_TELEMETRY_OBSERVED


def test_events_processed_cleanly():
    t = _loaded()
    t.record_message(_event_message())
    t.record_event_accepted("SmsManager.sendTextMessage")
    t.record_event_published()
    t.mark_window_end()
    assert t.classify({"dropped": 0, "subscriber_errors": 0}, {"failed": 0}) is C.RUNTIME_EVENTS_RECEIVED


@pytest.mark.parametrize("bus,store", [
    ({"dropped": 1, "subscriber_errors": 0}, {"failed": 0}),
    ({"dropped": 0, "subscriber_errors": 2}, {"failed": 0}),
    ({"dropped": 0, "subscriber_errors": 0}, {"failed": 1}),
    ({"dropped": 0, "subscriber_errors": 0}, {"failed": 0, "persist_failures": 1}),
])
def test_downstream_losses_are_processing_failures(bus, store):
    t = _loaded()
    t.record_message(_event_message())
    t.record_event_published()
    assert t.classify(bus, store) is C.EVENT_PROCESSING_FAILED


def test_unpublished_event_is_processing_failure():
    t = _loaded()
    t.record_message(_event_message())       # received, never published
    assert t.classify() is C.EVENT_PROCESSING_FAILED
    assert t.to_dict()["processing_losses"]["unpublished_events"] == 1


def test_filtered_event_is_not_a_loss():
    t = _loaded()
    t.record_message(_event_message())
    t.record_event_filtered()
    t.mark_window_end()
    assert t.classify() is C.RUNTIME_EVENTS_RECEIVED


def test_malformed_and_script_errors_counted():
    t = TelemetryDiagnostics()
    assert t.record_message("not a dict") is None
    assert t.record_message({"type": "send", "payload": "str"}) is None
    assert t.record_message({"type": "error", "description": "ReferenceError: x"}) is None
    d = t.to_dict()
    assert d["messages"]["malformed"] == 2
    assert d["agent"]["script_errors"] == ["ReferenceError: x"]


def test_error_lists_are_bounded():
    t = TelemetryDiagnostics()
    for i in range(500):
        t.record_hook_error(f"h{i}", "boom")
    d = t.to_dict()
    assert d["hooks"]["errors"] == 500
    assert len(d["hooks"]["error_samples"]) <= 20


def test_concurrent_recording_is_consistent():
    t = _loaded()

    def worker():
        for _ in range(1000):
            t.record_message(_event_message())
            t.record_event_published()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    d = t.to_dict()
    assert d["events"]["received"] == 8000
    assert d["events"]["published"] == 8000


# ── FridaSession message handling (mocked transport) ────────────────────────

@pytest.fixture
def fs(tmp_path):
    s = FridaSession("emulator-5554", "com.example", artifact_dir=tmp_path, case_id="case-x")
    yield s
    s.event_bus.close(2.0)


def test_session_routes_event_through_bus_to_evidence(fs):
    fs._on_message({"type": "send", "payload": {"type": "canary"}}, None)
    fs._on_message({"type": "send", "payload": {"type": "hook_installed", "hook": "SmsManager", "total": 1}}, None)
    fs._on_message(_event_message(), None)
    assert fs.event_bus.drain(5.0)
    fs.telemetry.mark_window_end()
    report = _finalize_session_telemetry(fs)
    assert report["classification"] == C.RUNTIME_EVENTS_RECEIVED.value
    assert report["events"] == {**report["events"], "received": 1, "accepted": 1, "published": 1}
    assert report["evidence_store"]["accepted"] == 1
    assert report["event_bus"]["delivered"] >= 1
    assert fs.evidence_store.count() == 1
    assert fs.event_bus.closed


def test_malformed_messages_never_raise(fs):
    for bad in (None, "x", 42, {"type": "send"}, {"type": "send", "payload": None},
                {"type": "send", "payload": {"type": "event", "payload": None}}):
        fs._on_message(bad, None)  # must not raise
    assert fs.telemetry.malformed_messages >= 4


def test_handler_exception_is_recorded_not_lost(fs, monkeypatch):
    class Exploding(dict):
        def __getitem__(self, key):
            raise RuntimeError("collector broken")

        def __contains__(self, key):
            return True

    fs.collected_events = Exploding()
    fs._on_message(_event_message(), None)  # must not raise
    d = fs.telemetry.to_dict()
    assert d["messages"]["handler_exceptions"] == 1
    assert "collector broken" in d["messages"]["handler_errors"][0]
    assert d["classification"] == C.EVENT_PROCESSING_FAILED.value


def test_companion_canary_does_not_count_as_primary_agent(fs):
    handler = fs._companion_message_handler("com.payload")
    handler({"type": "send", "payload": {"type": "canary"}}, None)
    handler({"type": "send", "payload": {"type": "hook_installed", "total": 40}}, None)
    assert fs.telemetry.canary_received is False
    assert fs.telemetry.hooks_installed == 0


def test_detached_callback_recorded(fs):
    class Crash:
        summary = "SIGSEGV"
        process_name = "com.example"
        pid = 99

    fs._on_detached("process-terminated", Crash())
    d = fs.telemetry.to_dict()
    assert d["session"]["detached"] is True
    assert d["session"]["detach_crash"]["summary"] == "SIGSEGV"


def test_load_primary_agent_records_failure_and_reraises(fs):
    class Sess:
        def on(self, *a):
            pass

        def create_script(self, src):
            raise ValueError("script(line 3): SyntaxError")

    fs._session = Sess()
    with pytest.raises(ValueError):
        fs._load_primary_agent("bad", 77)
    d = fs.telemetry.to_dict()
    assert d["attach"]["attached"] is True and d["attach"]["pid"] == 77
    assert "SyntaxError" in d["agent"]["load_error"]
    assert d["classification"] == C.AGENT_INIT_FAILED.value
    assert any("Agent load failed" in e for e in fs.hook_errors)


def test_load_primary_agent_registers_detach_handler(fs):
    registered = {}

    class Script:
        def on(self, sig, cb):
            registered[f"script:{sig}"] = cb

        def load(self):
            pass

    class Sess:
        def on(self, sig, cb):
            registered[f"session:{sig}"] = cb

        def create_script(self, src):
            return Script()

    fs._session = Sess()
    fs._load_primary_agent("ok", 5)
    assert "session:detached" in registered and "script:message" in registered
    assert fs._script is not None and fs.telemetry.agent_loaded
