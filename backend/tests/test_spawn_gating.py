"""
Regression tests for spawn-gated instrumentation.

The defect these lock down: the sandbox used to `am start` the app and attach
Frida afterwards. Measured on a real run, the process was alive at t+50s and
Frida attached at t+86s - so Application.onCreate, DEX loading and the first C2
beacon all ran with no hooks installed. That run finished with 77 hooks
installed and exactly one hook fire, which was the harness spoofing its own
Build fields. Whether a run captured anything depended on whether the sample
happened to act again after the attach, which is why dynamic analysis worked
only sometimes.

The contract now:
  * the agent is loaded while the process is SUSPENDED, and resume() happens
    strictly after script.load()
  * every process the sample spawns is caught and instrumented
  * a gated spawn is ALWAYS resumed, even when instrumenting it fails, because
    gating is device-wide and a process left suspended wedges the emulator
  * any failure in the spawn path falls back to the launch ladder rather than
    losing the run

No device needed - the frida Device is a mock.
"""
from __future__ import annotations

import time
from typing import Any, List, Optional
from unittest.mock import MagicMock, patch

import pytest


FS = "sudarshan_core.engines.frida_sandbox"


def _make_session(main_activity: Optional[str] = "com.test.bankbot.Main"):
    from sudarshan_core.engines.frida_sandbox import FridaSession

    return FridaSession(
        device_serial="emulator-5554",
        package_name="com.test.bankbot",
        main_activity=main_activity,
    )


class _FakeDevice:
    """Records the order of spawn/attach/load/resume against one process."""

    def __init__(self, *, spawn_pid: int = 4242, spawn_error: Exception | None = None):
        self.calls: List[str] = []
        self._spawn_pid = spawn_pid
        self._spawn_error = spawn_error
        self.killed: List[int] = []
        self.resumed: List[int] = []
        self.gating_enabled = False
        self.gating_disabled = False
        self._handlers: dict = {}

    def spawn(self, package: str) -> int:
        self.calls.append("spawn")
        if self._spawn_error:
            raise self._spawn_error
        return self._spawn_pid

    def attach(self, pid: Any):
        self.calls.append("attach")
        session = MagicMock()
        script = MagicMock()

        def _load():
            self.calls.append("script.load")

        script.load.side_effect = _load
        session.create_script.return_value = script
        return session

    def resume(self, pid: int) -> None:
        self.calls.append("resume")
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)

    def on(self, signal: str, cb) -> None:
        self._handlers[signal] = cb

    def enable_spawn_gating(self) -> None:
        self.gating_enabled = True

    def disable_spawn_gating(self) -> None:
        self.gating_disabled = True


# ── the ordering contract ─────────────────────────────────────────────────────


def test_agent_is_loaded_before_the_process_is_resumed():
    """
    The whole point of the spawn path. If resume() ran before script.load(),
    the app would execute its entry point uninstrumented and we would be back
    to the behaviour this fix exists to remove.
    """
    session = _make_session()
    device = _FakeDevice()

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}._poll_pid_until_stable", return_value=(True, 4242, "stable")), \
         patch(f"{FS}._adb", return_value=(True, "")), \
         patch(f"{FS}._resolve_launcher_activity", return_value=None):
        assert session._spawn_gated_launch(device, "// agent") is True

    assert device.calls.index("script.load") < device.calls.index("resume"), (
        f"agent must load before resume; got {device.calls}"
    )
    assert session.spawn_gated is True
    assert session.launch_method_used == "spawn_gated"
    assert session._stable_pid == 4242


def test_spawn_gated_run_records_an_early_attach_timestamp():
    """
    frida_attach must be stamped by the spawn path, so a report can prove the
    hooks were in place before the app ran rather than 36s after.
    """
    session = _make_session()
    device = _FakeDevice()

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}._poll_pid_until_stable", return_value=(True, 4242, "stable")), \
         patch(f"{FS}._adb", return_value=(True, "")), \
         patch(f"{FS}._resolve_launcher_activity", return_value=None):
        session._spawn_gated_launch(device, "// agent")

    assert session.launch_timeline["frida_attach"] is not None
    assert session.launch_timeline["first_pid"] is not None
    # attach must not come after the process was already running and settled
    assert session.launch_timeline["frida_attach"] >= session.launch_timeline["first_pid"]


# ── fallback behaviour ────────────────────────────────────────────────────────


def test_spawn_failure_falls_back_to_the_ladder_without_a_session():
    """A sample that cannot be spawned must behave exactly as it did before."""
    session = _make_session()
    device = _FakeDevice(spawn_error=RuntimeError("unable to spawn"))

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}.SPAWN_MAX_ATTEMPTS", 1), \
         patch(f"{FS}._poll_pid_until_stable", return_value=(True, 1, "stable")), \
         patch(f"{FS}._adb", return_value=(True, "")):
        assert session._spawn_gated_launch(device, "// agent") is False

    assert session.spawn_gated is False
    assert session._session is None
    assert session._script is None
    assert "unable to spawn" in session.spawn_fallback_reason


def test_process_that_dies_after_resume_falls_back():
    """
    A sample that crashes under instrumentation has not launched. Reporting it
    as a successful spawn would attribute silence to the sample.
    """
    session = _make_session()
    device = _FakeDevice()

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}._poll_pid_until_stable", return_value=(False, None, "exited after 0.4s")), \
         patch(f"{FS}._adb", return_value=(True, "")), \
         patch(f"{FS}._resolve_launcher_activity", return_value=None):
        assert session._spawn_gated_launch(device, "// agent") is False

    assert session.spawn_gated is False
    assert session._session is None
    assert session._stable_pid is None
    assert "died after resume" in session.spawn_fallback_reason


def test_self_restarting_sample_falls_back():
    """
    Some loaders restart themselves. Our session would then be attached to a
    process that no longer matters, so the honest answer is the ladder.
    """
    session = _make_session()
    device = _FakeDevice(spawn_pid=100)

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}._poll_pid_until_stable", return_value=(True, 999, "stable")), \
         patch(f"{FS}._adb", return_value=(True, "")), \
         patch(f"{FS}._resolve_launcher_activity", return_value=None):
        assert session._spawn_gated_launch(device, "// agent") is False

    assert "restarted" in session.spawn_fallback_reason


# ── gated child processes ─────────────────────────────────────────────────────


def _spawn_obj(pid: int, identifier: str):
    s = MagicMock()
    s.pid = pid
    s.identifier = identifier
    return s


def test_payload_process_is_instrumented_when_gated():
    """
    The dropper case. Previously the payload package ran entirely
    uninstrumented, because companion detection only ran before exploration
    started and the hand-off happens mid-run.
    """
    session = _make_session()
    device = _FakeDevice()
    session._third_party_packages = {"com.tjmonh.android"}
    session._third_party_fetched_at = time.monotonic()

    session._instrument_gated_spawn(device, 777, "com.tjmonh.android", "// agent")

    assert "com.tjmonh.android" in session._companion_sessions
    assert "com.tjmonh.android" in session.companion_packages
    assert 777 in device.resumed
    assert device.calls.index("script.load") < device.calls.index("resume")


def test_gated_spawn_is_resumed_even_when_instrumentation_fails():
    """
    Gating is device-wide. A process left suspended because we could not hook
    it would wedge the emulator - a worse failure than the missed hook.
    """
    session = _make_session()
    device = _FakeDevice()
    device.attach = MagicMock(side_effect=RuntimeError("permission denied"))
    session._third_party_packages = {"com.tjmonh.android"}
    session._third_party_fetched_at = time.monotonic()

    session._instrument_gated_spawn(device, 778, "com.tjmonh.android", "// agent")

    assert 778 in device.resumed, "a gated spawn must always be resumed"
    assert "com.tjmonh.android" not in session._companion_sessions


def test_system_packages_are_resumed_but_not_instrumented():
    """
    Gating catches every process on the device. Attaching to the launcher and
    to Settings would burn the run's time budget and produce no evidence about
    the sample.
    """
    session = _make_session()
    device = _FakeDevice()
    session._third_party_packages = set()
    session._third_party_fetched_at = time.monotonic()

    session._instrument_gated_spawn(
        device, 55, "com.google.android.apps.nexuslauncher", "// agent"
    )

    assert 55 in device.resumed
    assert "attach" not in device.calls
    assert session._companion_sessions == {}


def test_target_is_not_double_instrumented():
    """
    The target's primary session is created by _spawn_gated_launch. A second
    agent in the same process would install every hook twice and double-count
    every event the sample produces.
    """
    session = _make_session()
    session._session = MagicMock()          # primary session already established
    device = _FakeDevice()
    session._third_party_packages = {"com.test.bankbot"}
    session._third_party_fetched_at = time.monotonic()

    session._instrument_gated_spawn(device, 4242, "com.test.bankbot", "// agent")

    assert "attach" not in device.calls
    assert 4242 in device.resumed


# ── gating lifecycle ──────────────────────────────────────────────────────────


def test_enable_spawn_gating_registers_a_handler_and_turns_gating_on():
    session = _make_session()
    device = _FakeDevice()

    assert session._enable_spawn_gating(device, "// agent") is True
    assert device.gating_enabled is True
    assert "spawn-added" in device._handlers
    assert session._spawn_gating_enabled is True


def test_unsupported_gating_degrades_instead_of_failing_the_run():
    """
    A device that cannot gate still produces a usable run via the existing
    companion-polling path.
    """
    session = _make_session()
    device = _FakeDevice()
    device.enable_spawn_gating = MagicMock(side_effect=RuntimeError("not supported"))

    assert session._enable_spawn_gating(device, "// agent") is False
    assert session._spawn_gating_enabled is False


# ── the run reports its own instrumentation latency honestly ──────────────────


def _session_with(collected, timeline, *, spawn_gated=False):
    session = _make_session()
    session.collected_events = collected
    session.launch_timeline.update(timeline)
    session.spawn_gated = spawn_gated
    return session


def test_harness_only_events_do_not_count_as_observed_behaviour():
    """
    A real run held exactly {harness_action: 1} - the agent spoofing its own
    Build fields, which fires on every emulator run for benign apps and trojans
    alike - and reported EVENTS_CAPTURED. The report then read as "the sample
    was observed and did nothing", which is the opposite of what happened.
    """
    from sudarshan_core.engines.frida_sandbox import _no_sample_behaviour_observed

    session = _make_session()
    session.collected_events = {
        "harness_action": [{"hook": "Build.<static fields>"}],
        "anti_analysis": [],
        "accessibility": [],
    }
    assert _no_sample_behaviour_observed(session) is True

    session.collected_events["accessibility"] = [
        {"hook": "AccessibilityNodeInfo.getText"}
    ]
    assert _no_sample_behaviour_observed(session) is False


def test_build_field_spoof_filed_under_anti_analysis_is_still_the_harness():
    """Older agents file the harness's own spoof under anti_analysis."""
    from sudarshan_core.engines.frida_sandbox import _no_sample_behaviour_observed

    session = _make_session()
    session.collected_events = {
        "anti_analysis": [{"data": {"hook": "Build.<static fields>"}}],
    }
    assert _no_sample_behaviour_observed(session) is True


def test_late_attach_is_detected():
    from sudarshan_core.engines.frida_sandbox import _instrumentation_was_late

    # The measured run: process alive at t=50, agent loaded at t=86.
    session = _session_with({}, {"first_pid": 50.0, "frida_attach": 86.2})
    assert _instrumentation_was_late(session) is True


def test_spawn_gated_run_is_never_late_by_construction():
    """
    The agent is loaded into a SUSPENDED process, so nothing executed before
    the hooks were in. This is what makes INSTRUMENTED_TOO_LATE a regression
    detector rather than a label every run carries.
    """
    from sudarshan_core.engines.frida_sandbox import _instrumentation_was_late

    session = _session_with(
        {}, {"first_pid": 50.0, "frida_attach": 86.2}, spawn_gated=True,
    )
    assert _instrumentation_was_late(session) is False


def test_prompt_attach_is_not_late():
    from sudarshan_core.engines.frida_sandbox import _instrumentation_was_late

    session = _session_with({}, {"first_pid": 10.0, "frida_attach": 11.2})
    assert _instrumentation_was_late(session) is False


def test_unknown_latency_on_the_ladder_path_counts_as_late():
    """
    The ladder always waits for a stable PID before attaching, so an unreadable
    timeline on that path cannot mean "early". Guessing early would restore the
    silent zero this status exists to prevent.
    """
    from sudarshan_core.engines.frida_sandbox import _instrumentation_was_late

    session = _session_with({}, {"first_pid": None, "frida_attach": None})
    assert _instrumentation_was_late(session) is True


def test_too_late_status_excludes_the_dynamic_axis():
    """
    Scoring the fraud axis from a run that measured only the harness would
    award a clean zero at 0.35 weight for having observed nothing.
    """
    from sudarshan_core.engines.risk_engine import dynamic_exclusion_reason

    reason = dynamic_exclusion_reason({
        "available": True,
        "runtime_attempted": True,
        "dynamic_status": "INSTRUMENTED_TOO_LATE",
        "bfci": 0.0,
    })
    assert reason == "INSTRUMENTED_TOO_LATE"


# ── third-party classification must see packages installed mid-run ────────────


def test_a_package_installed_mid_run_is_recognised_after_the_ttl():
    """
    The dropper case, and the reason this cache holds a SET with a TTL rather
    than one answer per package.

    A negative used to be cached forever: the payload was asked about before it
    existed, answered False, and never re-asked - so the very package the
    engine exists to catch could never be classified as third party, and
    therefore never instrumented.
    """
    from sudarshan_core.engines.frida_sandbox import FridaSession

    session = _make_session()
    listings = iter([
        (True, "package:com.test.bankbot"),                      # before install
        (True, "package:com.test.bankbot\npackage:com.tjmonh.android"),
    ])

    with patch(f"{FS}._adb", side_effect=lambda *a, **k: next(listings)):
        assert session._is_third_party("com.tjmonh.android") is False
        # TTL expiry, as it would during a 300s exploration window
        session._third_party_fetched_at -= 60.0
        assert session._is_third_party("com.tjmonh.android") is True


def test_repeated_questions_inside_the_ttl_cost_no_adb_calls():
    """
    Under device-wide gating this runs on frida's callback thread while a
    process is SUSPENDED. An adb round trip per unseen package name would hold
    system processes suspended long enough to matter.
    """
    from sudarshan_core.engines.frida_sandbox import FridaSession

    session = _make_session()
    adb = MagicMock(return_value=(True, "package:com.test.bankbot"))

    with patch(f"{FS}._adb", adb):
        for name in ("com.a", "com.b", "com.c", "com.test.bankbot"):
            session._is_third_party(name)

    assert adb.call_count == 1


def test_an_unreadable_device_is_not_frozen_into_a_negative():
    """A failed read must not be cached as 'nothing here is third party'."""
    from sudarshan_core.engines.frida_sandbox import FridaSession

    session = _make_session()
    with patch(f"{FS}._adb", return_value=(False, "")):
        assert session._is_third_party("com.tjmonh.android") is False
    with patch(f"{FS}._adb", return_value=(True, "package:com.tjmonh.android")):
        assert session._is_third_party("com.tjmonh.android") is True


# ── spawn timeout must be bounded, and recoverable ───────────────────────────


class _HangingSpawnDevice(_FakeDevice):
    """device.spawn() that never returns, as frida#3743 reports on Android."""

    def __init__(self, block: "threading.Event"):
        super().__init__()
        self._block = block

    def spawn(self, package: str) -> int:
        self.calls.append("spawn")
        self._block.wait(30)
        raise RuntimeError("unexpectedly timed out while waiting for app to launch")


def test_a_hanging_spawn_is_actually_bounded_by_our_timeout():
    """
    ThreadPoolExecutor.__exit__ calls shutdown(wait=True), so wrapping the
    submit in `with` made the timeout decorative - a hanging spawn still hung.
    Measured before this fix: a 30s bound produced a 67s stall, which was
    frida's own internal timeout rather than ours.
    """
    import threading as _t

    block = _t.Event()
    session = _make_session()
    device = _HangingSpawnDevice(block)

    started = time.monotonic()
    try:
        with patch(f"{FS}._force_stop_package"), \
             patch(f"{FS}.SPAWN_TIMEOUT_SECONDS", 1.0), \
             patch(f"{FS}._adb", return_value=(True, "")), \
             patch.object(type(session), "_resolve_pid", lambda self: None):
            assert session._spawn_gated_launch(device, "// agent") is False
        elapsed = time.monotonic() - started
    finally:
        block.set()

    assert elapsed < 10, f"spawn was not bounded: took {elapsed:.1f}s"
    assert session.spawn_gated is False


def test_unconfirmed_spawn_attaches_to_the_running_process():
    """
    "unexpectedly timed out while waiting for app to launch" is a known Android
    issue (frida#3743, #2005, #1737) in which the app DOES launch and only the
    confirmation times out. Restarting it through the full ladder costs ~100s
    and lands on the same process, so attach to it now.
    """
    import threading as _t

    block = _t.Event()
    session = _make_session()
    device = _HangingSpawnDevice(block)

    try:
        with patch(f"{FS}._force_stop_package"), \
             patch(f"{FS}.SPAWN_TIMEOUT_SECONDS", 1.0), \
             patch(f"{FS}._poll_pid_until_stable", return_value=(True, 5150, "stable")), \
             patch(f"{FS}._adb", return_value=(True, "")), \
             patch(f"{FS}._resolve_launcher_activity", return_value=None), \
             patch.object(type(session), "_resolve_pid", lambda self: 5150):
            assert session._spawn_gated_launch(device, "// agent") is True
    finally:
        block.set()

    assert session._stable_pid == 5150
    assert session.launch_method_used == "spawn_recovered_attach"
    # We did NOT suspend this process, so it must never be resumed...
    assert device.resumed == []
    # ...and the run must not claim pre-first-instruction coverage it lacks.
    assert session.spawn_gated is False


def test_a_recovered_attach_is_still_subject_to_the_late_check():
    """
    spawn_gated stays False on the recovery path, so a recovered attach that
    was in fact too late is still reported as INSTRUMENTED_TOO_LATE rather than
    being waved through by the spawn flag.
    """
    from sudarshan_core.engines.frida_sandbox import _instrumentation_was_late

    session = _session_with(
        {}, {"first_pid": 10.0, "frida_attach": 80.0}, spawn_gated=False,
    )
    assert _instrumentation_was_late(session) is True


# ── the frida callback thread must never block ───────────────────────────────


def test_spawn_handler_does_no_frida_work_on_the_callback_thread():
    """
    frida-python's `_invoke` dispatches every API call onto frida's main
    context and waits for the reply. The `spawn-added` handler RUNS on that
    context, so calling device.attach() from it waits on itself.

    Observed exactly that: two threads parked forever in
    `frida/__init__.py:210 _invoke -> Event.wait()`, one from this handler and
    one from the launch ladder's own attach, and the run went silent.

    The handler must therefore touch nothing but the queue.
    """
    session = _make_session()
    device = _FakeDevice()

    session._on_spawn_added(_spawn_obj(777, "com.tjmonh.android"))

    assert device.calls == [], "the handler must not call into frida"
    assert session._spawn_queue.get_nowait() == (777, "com.tjmonh.android")


def test_worker_instruments_queued_spawns_and_stops_on_the_sentinel():
    import threading as _t

    session = _make_session()
    device = _FakeDevice()
    session._third_party_packages = {"com.tjmonh.android"}
    session._third_party_fetched_at = time.monotonic()

    session._spawn_queue.put((777, "com.tjmonh.android"))
    session._spawn_queue.put(None)

    worker = _t.Thread(target=session._spawn_worker, args=(device, "// agent"))
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive(), "worker must exit on the sentinel"
    assert "com.tjmonh.android" in session._companion_sessions
    assert 777 in device.resumed


def test_a_failing_spawn_does_not_kill_the_worker():
    """
    One bad spawn must not stop the queue being drained - every remaining item
    is a process left suspended.
    """
    import threading as _t

    session = _make_session()
    device = _FakeDevice()
    session._third_party_packages = {"com.a", "com.b"}
    session._third_party_fetched_at = time.monotonic()

    calls = []
    original = session._instrument_gated_spawn

    def _boom(dev, pid, identifier, src):
        calls.append(identifier)
        if identifier == "com.a":
            raise RuntimeError("attach exploded")
        return original(dev, pid, identifier, src)

    session._instrument_gated_spawn = _boom
    session._spawn_queue.put((1, "com.a"))
    session._spawn_queue.put((2, "com.b"))
    session._spawn_queue.put(None)

    worker = _t.Thread(target=session._spawn_worker, args=(device, "// agent"))
    worker.start()
    worker.join(timeout=5)

    assert calls == ["com.a", "com.b"]
    assert 2 in device.resumed


def test_gating_is_disabled_before_the_ladder_fallback():
    """
    With gating left on, the ladder's `am start` is caught at spawn and
    instrumented just as early as the attempt that just died - so a sample that
    cannot survive early instrumentation crashes again and the run ends as
    INSTRUMENTATION_FAILED. Measured on Anubis: it died in Application.onCreate
    on the spawn attempt AND on the ladder relaunch.

    The ladder's value here is precisely that it attaches late.
    """
    session = _make_session()
    device = _FakeDevice()

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}._poll_pid_until_stable", return_value=(False, None, "exited after 3.5s")), \
         patch(f"{FS}._adb", return_value=(True, "")), \
         patch(f"{FS}._resolve_launcher_activity", return_value=None):
        session._enable_spawn_gating(device, "// agent")
        assert session._spawn_gating_enabled is True
        assert session._spawn_gated_launch(device, "// agent") is False

    assert device.gating_disabled is True
    assert session._spawn_gating_enabled is False


def test_art_heap_daemon_segv_is_recognised_as_an_instrumentation_race():
    """
    Measured on Anubis under spawn gating: "Fatal signal 11 (SIGSEGV), code 1
    (SEGV_MAPERR), fault addr 0x0 in tid 8152 (HeapTaskDaemon)". Same
    phenomenon as the JIT thread - an ART daemon tripping over methods being
    instrumented underneath it - and now more likely, because hooks go in during
    startup when those daemons are busiest.
    """
    from sudarshan_core.engines.frida_sandbox import (
        CrashReport, _crash_is_instrumentation_race,
    )

    report = CrashReport(package_name="com.tjmonh.android")
    report.native_stacktrace = (
        "F/libc (8148): Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), "
        "fault addr 0x0 in tid 8152 (HeapTaskDaemon), pid 8148"
    )
    assert _crash_is_instrumentation_race(report) is True


def test_a_java_exception_still_stops_the_ladder():
    """A sample that throws is a sample that crashed - never retried."""
    from sudarshan_core.engines.frida_sandbox import (
        CrashReport, _crash_is_instrumentation_race,
    )

    report = CrashReport(package_name="com.tjmonh.android")
    report.exception_type = "java.lang.RuntimeException"
    report.native_stacktrace = "tid 8152 (HeapTaskDaemon) SIGSEGV"
    assert _crash_is_instrumentation_race(report) is False


# ── every fallback must actually fall back ───────────────────────────────────


def test_gating_is_disabled_when_spawn_itself_fails():
    """
    The path that broke a live run. spawn() failed with "unable to find a
    front-door activity", the ladder took over - and because gating was still
    on, the ladder's own `am start` was caught at spawn and instrumented just
    as early:

        SPAWN_GATED_INSTRUMENTED com.android.s4protect (pid=13060)
        Process ... exited after 0.6s - app crashed before becoming stable

    java.lang.RuntimeException in Application.onCreate, run ended
    INSTRUMENTATION_FAILED with no dynamic evidence - on a fallback that had
    never actually fallen back.
    """
    session = _make_session()
    device = _FakeDevice(
        spawn_error=RuntimeError("unable to find a front-door activity"),
    )

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}.SPAWN_MAX_ATTEMPTS", 1), \
         patch(f"{FS}._adb", return_value=(True, "")), \
         patch.object(type(session), "_resolve_pid", lambda self: None):
        session._enable_spawn_gating(device, "// agent")
        assert session._spawn_gating_enabled is True
        assert session._spawn_gated_launch(device, "// agent") is False

    assert device.gating_disabled is True
    assert session._spawn_gating_enabled is False


def test_gating_is_disabled_when_the_agent_cannot_be_loaded():
    session = _make_session()
    device = _FakeDevice()

    def _bad_attach(pid):
        device.calls.append("attach")
        raise RuntimeError("permission denied")

    device.attach = _bad_attach

    with patch(f"{FS}._force_stop_package"), \
         patch(f"{FS}._adb", return_value=(True, "")):
        session._enable_spawn_gating(device, "// agent")
        assert session._spawn_gated_launch(device, "// agent") is False

    assert device.gating_disabled is True


def test_every_failure_path_leaves_gating_off():
    """
    A path added later must not reintroduce the gap. Whatever makes the spawn
    path give up, the ladder that follows has to be a genuinely late attach.
    """
    import inspect

    from sudarshan_core.engines.frida_sandbox import FridaSession

    src = inspect.getsource(FridaSession._spawn_gated_launch)
    body_returns = src.count("return False")
    disables = src.count("_disable_gating_for_fallback")
    assert disables >= body_returns, (
        f"{body_returns} failure returns but only {disables} gating disables - "
        "some path hands back to the ladder with gating still on"
    )
