"""The anti-evasion sequence as the sandbox runs it, mid-session.

Timing is the whole feature. Run at the end of exploration, the sequence
compares hook counters belonging to a live process; run after the session, it
can only ever report that nothing was observed. These tests pin the wiring that
makes the first case possible: the per-session telemetry probe, the result
reaching the dynamic result, and a failure staying a degraded run rather than a
failed analysis.
"""

import pytest

frida_sandbox = pytest.importorskip("sudarshan_core.engines.frida_sandbox")

FridaSession = frida_sandbox.FridaSession


def _session(**attrs):
    session = FridaSession("emulator-5554", "com.evil.dropper")
    for key, value in attrs.items():
        setattr(session, key, value)
    return session


# ── Per-session telemetry probe ────────────────────────────────────────────


def test_probe_counts_this_session_only():
    session = _session(canary_received=True, java_hooks_installed=17)
    session.collected_events["sms"].extend([{"hook": "getMessageBody"}] * 3)
    session.collected_events["network"].append({"hook": "HttpURLConnection"})

    snapshot = session._hook_telemetry_snapshot()

    assert snapshot["attached"] is True
    assert snapshot["counts"]["sms"] == 3
    assert snapshot["counts"]["network"] == 1
    assert snapshot["counts"]["overlay"] == 0


def test_probe_is_not_attached_without_a_canary():
    """No canary means the script never loaded; its counters mean nothing."""
    session = _session(canary_received=False, java_hooks_installed=17)
    assert session._hook_telemetry_snapshot()["attached"] is False


def test_probe_is_not_attached_when_the_java_bridge_failed():
    """
    Hooks that were never installed cannot fire.

    Reporting their silence as "zero SMS reads" would convert an
    instrumentation fault into a finding about the sample - the exact
    substitution the dynamic axis exists to prevent.
    """
    session = _session(
        canary_received=True, java_hooks_installed=0, java_bridge_failed=True
    )
    assert session._hook_telemetry_snapshot()["attached"] is False


# ── Sequence invocation ────────────────────────────────────────────────────


class _FakeOrchestrator:
    """Stands in for the real orchestrator; records how it was constructed."""

    last: dict = {}

    def __init__(self, serial, package, *, telemetry_probe=None, **kwargs):
        _FakeOrchestrator.last = {
            "serial": serial,
            "package": package,
            "probe": telemetry_probe,
        }

    def run_sequence(self, **kwargs):
        _FakeOrchestrator.last["run_kwargs"] = kwargs

        class _Result:
            verdict = "NO_CHANGES_OBSERVED"
            triggered_keys: list = []

            @staticmethod
            def to_dict():
                return {"verdict": "NO_CHANGES_OBSERVED", "deltas": []}

        return _Result()


def test_sequence_result_is_stored_on_the_session(monkeypatch):
    import sudarshan_core.engines.anti_evasion as anti_evasion

    monkeypatch.setattr(anti_evasion, "AntiEvasionOrchestrator", _FakeOrchestrator)
    session = _session(canary_received=True, java_hooks_installed=17)
    monkeypatch.setattr(session, "_capture_screenshot", lambda *a, **k: None)

    session._run_anti_evasion_sequence()

    assert session.anti_evasion_result == {"verdict": "NO_CHANGES_OBSERVED", "deltas": []}
    # The device and package under analysis, and this session's own counters.
    assert _FakeOrchestrator.last["serial"] == "emulator-5554"
    assert _FakeOrchestrator.last["package"] == "com.evil.dropper"
    assert _FakeOrchestrator.last["probe"] == session._hook_telemetry_snapshot
    # The device is handed back in the state the next sample expects.
    assert _FakeOrchestrator.last["run_kwargs"]["restore"] is True


def test_a_failed_sequence_leaves_the_run_intact(monkeypatch):
    """A sandbox control failing must not cost the analyst the telemetry so far."""
    import sudarshan_core.engines.anti_evasion as anti_evasion

    def _explode(*_a, **_k):
        raise RuntimeError("adb went away")

    monkeypatch.setattr(anti_evasion, "AntiEvasionOrchestrator", _explode)
    session = _session()

    session._run_anti_evasion_sequence()

    # None, not an empty result: "not measured" must not read as "measured, and
    # nothing happened".
    assert session.anti_evasion_result is None


def test_the_sequence_is_switchable():
    """Every dynamic run pays ~15s for it, so operators can turn it off."""
    assert isinstance(frida_sandbox.ANTI_EVASION_ENABLED, bool)
    assert frida_sandbox.ANTI_EVASION_OBSERVE_SECONDS > 0
