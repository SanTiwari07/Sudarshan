"""
A process without a window is still a process.

Measured live on Anubis, 300-second run:

    Launch step 'am_start_main_activity'      PID 12966, no foreground window
    Launch step 'main_launcher_intent'        PID 12966, no foreground window
    Launch step 'resolved_launcher_activity'  PID 12966, no foreground window
    Launch step 'exported_activity:.Main'     PID 12966, no foreground window
    Launch step 'boot_broadcast'              PID 12966, no foreground window
    Launch step 'force_stop_retry'            -> crashed after 10.8s
    "Application crashed during step6_force_stop_retry - NOT attaching Frida."

    status=INSTRUMENTATION_FAILED, hooks_installed=0, events=0

The app ran headless for six consecutive steps - the SAME pid each time, so it
was stable and attachable. That is the behaviour of a dropper, not a launch
failure. Step 6 force-stops the package before retrying, which destroyed the
only observation target we had, and the ui-less fallback is gated on no crash
having occurred - so a viable process was discarded.

These tests pin both halves of the correction at the source level: the
destructive step is skipped once a headless process exists, and a crash on a
later step cannot veto an earlier process that is still alive.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

_SANDBOX = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_sandbox.py"


@pytest.fixture(scope="module")
def source() -> str:
    return _SANDBOX.read_text(encoding="utf-8", errors="replace")


def test_the_force_stop_step_is_skipped_when_a_headless_process_exists(source):
    """
    Step 6 force-stops the package first. Running it against a live headless
    process can only lose it.
    """
    idx = source.index("Step 6 - force-stop then retry resolved launcher")
    guard = source[idx:idx + 1400]
    condition = re.search(r"if not launched and [^\n]*:", guard)
    assert condition, "step 6 has no guard at all"
    assert "_ui_less_pid is None" in condition.group(0), (
        "step 6 still runs when a headless process is already available; "
        "force-stopping it destroys the only attachable target"
    )


def test_the_fallback_is_not_vetoed_by_a_later_crash(source):
    """
    The old condition required `_crash_on_step is None`, so a crash in a LATER
    escalation discarded a process an EARLIER step had established.
    """
    idx = source.index("A crash on a LATER, more aggressive step")
    block = source[idx:idx + 1200]
    condition = re.search(r"if not launched and _ui_less_pid is not None:", block)
    assert condition, "the ui-less fallback no longer exists"
    # It must NOT re-introduce the veto.
    head = block[:block.index("\n", condition.end())] if condition else ""
    assert "_crash_on_step is None" not in head


def test_the_fallback_verifies_the_process_is_still_alive(source):
    """
    Dropping the crash veto without a liveness check would attach to a dead
    pid and report a successful run that observed nothing.
    """
    idx = source.index("A crash on a LATER, more aggressive step")
    block = source[idx:idx + 1400]
    assert "_resolve_pid()" in block
    assert "_still_alive" in block


def test_the_liveness_helper_exists(source):
    """A typo here fails at runtime, inside a 300-second run, on a device."""
    from sudarshan_core.engines.frida_sandbox import FridaSession

    assert hasattr(FridaSession, "_resolve_pid")


def test_a_headless_run_is_still_marked_inconclusive(source):
    """
    Attaching to a window-less process must not let the run read as a normal
    one: no UI rendered means limited coverage, and the risk engine needs to
    know so it can exclude the dynamic axis rather than score the silence.
    """
    idx = source.index("A crash on a LATER, more aggressive step")
    block = source[idx:idx + 1600]
    assert "self.ui_render_failed = True" in block
