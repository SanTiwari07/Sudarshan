"""
A stalled app is not a dead app, and must not retire the crash budget.

Attaching Frida and installing ~70 hooks runs on the app's main thread, so the
app misses its window-focus event and Android reports:

    ANR in com.hsjjsjs.android
    Reason: Input dispatching timed out (... is not responding.
            Waited 5002ms for FocusEvent(hasFocus=true)).

That dialog appears once per attach, "Wait" clears it, and the app then behaves
normally. Counting each one as a crash spent the 3-crash budget before the walk
had taken an action: measured exploration stopping at 2 actions on 0 screens
with the four-field form never reached.

A genuinely dead app must still end the run - that is what the crash budget is
for - so the two are separated on one question: is the process still there?
"""

import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))


def test_a_survivable_anr_has_its_own_larger_budget():
    from sudarshan_core.engines import agentic_explorer as ax

    assert ax.MAX_SURVIVABLE_ANRS > ax.MAX_CONSECUTIVE_CRASHES


def test_both_budgets_are_configurable(monkeypatch):
    """An operator investigating a genuinely wedged sample can tighten these."""
    import importlib

    from sudarshan_core.engines import agentic_explorer as ax

    monkeypatch.setenv("SUDARSHAN_MAX_SURVIVABLE_ANRS", "2")
    monkeypatch.setenv("SUDARSHAN_MAX_CONSECUTIVE_CRASHES", "1")
    reloaded = importlib.reload(ax)
    try:
        assert reloaded.MAX_SURVIVABLE_ANRS == 2
        assert reloaded.MAX_CONSECUTIVE_CRASHES == 1
    finally:
        monkeypatch.delenv("SUDARSHAN_MAX_SURVIVABLE_ANRS", raising=False)
        monkeypatch.delenv("SUDARSHAN_MAX_CONSECUTIVE_CRASHES", raising=False)
        importlib.reload(ax)


# ─── Liveness is what separates the two ──────────────────────────────────────

class _Explorer:
    """The two methods under test, lifted off a real AgenticExplorer."""

    def __init__(self, pid=0, companions=(), companion_pids=None):
        from sudarshan_core.engines.agentic_explorer import AgenticExplorer

        self._pid = pid
        self.device_serial = "emulator-5554"
        self.package_name = "com.loader.sample"
        self._companion_pids = companion_pids or {}

        class _Exploration:
            pass

        self.exploration = _Exploration()
        self.exploration.companion_packages = set(companions)
        self._resolve_target_pid = lambda: self._pid
        self._target_process_is_alive = (
            AgenticExplorer._target_process_is_alive.__get__(self)
        )


def _alive(explorer) -> bool:
    import asyncio

    return asyncio.run(explorer._target_process_is_alive())


def test_a_running_target_is_alive():
    assert _alive(_Explorer(pid=4242)) is True


def test_a_dead_target_with_no_companion_is_not_alive(monkeypatch):
    """
    A crash dialog over a process that is gone is a crash, and still ends the
    run on the smaller budget.
    """
    from sudarshan_core import sandbox

    class _Provider:
        def adb(self, *a, **k):
            return True, ""

    monkeypatch.setattr(sandbox, "get_sandbox_provider", lambda: _Provider())
    assert _alive(_Explorer(pid=0)) is False


def test_an_anr_over_the_companion_is_still_survivable(monkeypatch):
    """
    The companion is the app the victim is actually looking at. A stall in the
    package rendering the journey is a stall in this investigation.
    """
    from sudarshan_core import sandbox

    class _Provider:
        def adb(self, *a, **k):
            return True, "5893\n"

    monkeypatch.setattr(sandbox, "get_sandbox_provider", lambda: _Provider())
    explorer = _Explorer(pid=0, companions=("com.payload.sample",))
    assert _alive(explorer) is True


def test_an_unreadable_device_does_not_escalate(monkeypatch):
    """
    A pid reading that fails is a missing fact, not evidence of death. Treat it
    as survivable and let the ordinary budget end the run if the app is gone.
    """
    from sudarshan_core import sandbox

    def _boom():
        raise RuntimeError("adb gone")

    class _Provider:
        def adb(self, *a, **k):
            raise RuntimeError("adb gone")

    monkeypatch.setattr(sandbox, "get_sandbox_provider", lambda: _Provider())
    explorer = _Explorer(pid=0, companions=("com.payload.sample",))
    # Companion probe raises and is swallowed; nothing proved alive.
    assert _alive(explorer) is False
