"""Time Warp: clock advance, API-level syntax probing, deferred-work release.

The device is simulated, including its failure modes - notably the one that
matters most: Android's `date` exits 0 on several images while leaving the
clock exactly where it was. Trusting that exit code is what made the UI report
a warp that never happened.
"""

import calendar
import datetime
import re
from typing import List, Tuple

import pytest

from sudarshan_core.engines.time_warp import MAX_WARP_HOURS, TimeWarpEngine

DUMPSYS_JOBS = """
JOB SCHEDULER STATE
Registered 3 jobs:
  JOB #u0a188/12: 1a2b3c com.evil.dropper/.SyncWorker
    Required constraints: TIMING_DELAY
  JOB #u0a188/77: 4d5e6f com.evil.dropper/.FetchWorker
    Required constraints: CONNECTIVITY
  JOB #u0a99/5: 9z8y7x com.other.app/.Worker
"""


class FakeDevice:
    def __init__(self, api=33, clock_settable=True, jobs_ok=True, toolbox_only=False):
        self.api = api
        self.clock_settable = clock_settable
        self.jobs_ok = jobs_ok
        self.toolbox_only = toolbox_only
        self.epoch = 1_760_000_000
        self.auto_time = 1
        self.commands: List[str] = []

    def adb_shell(self, serial: str, command: str, timeout: int = 30) -> Tuple[bool, str]:
        self.commands.append(command)
        if command.startswith("getprop ro.build.version.sdk"):
            return True, str(self.api)
        if command == "date +%s":
            return True, str(self.epoch)
        if command.startswith("settings put global auto_time"):
            self.auto_time = int(command.rsplit(" ", 1)[1])
            return True, ""
        if command.startswith("date "):
            if self.clock_settable:
                self._apply_date(command.split(" ", 1)[1])
            # Exits 0 either way - the real-world behaviour.
            return True, ""
        if command == "dumpsys jobscheduler":
            return True, DUMPSYS_JOBS
        if command.startswith("cmd jobscheduler run"):
            return (True, "Running job") if self.jobs_ok else (False, "Error: no such job")
        return True, ""

    def _apply_date(self, arg: str) -> None:
        if arg.startswith("@"):
            if not self.toolbox_only:
                self.epoch = int(arg[1:])
            return
        if arg.startswith("-s "):
            # toolbox: YYYYMMDD.HHmmss
            m = re.match(r"-s (\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})(\d{2})$", arg)
            if m:
                y, mo, d, h, mi, s = (int(x) for x in m.groups())
                self.epoch = calendar.timegm(datetime.datetime(y, mo, d, h, mi, s).timetuple())
            return
        if self.toolbox_only:
            return
        # toybox: MMDDhhmmYYYY.ss
        m = re.match(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{4})\.(\d{2})$", arg)
        if m:
            mo, d, h, mi, y, s = (int(x) for x in m.groups())
            self.epoch = calendar.timegm(datetime.datetime(y, mo, d, h, mi, s).timetuple())


# ── Clock ──────────────────────────────────────────────────────────────────


def test_clock_advances_on_a_modern_device():
    device = FakeDevice(api=33)
    result = TimeWarpEngine("x", provider=device).fast_forward_time(24, force_jobs=False)
    assert result.ok
    assert result.observed_shift_hours == pytest.approx(24.0, abs=0.05)
    assert result.method == "toybox"


def test_legacy_device_uses_toolbox_syntax():
    """API < 23 shipped toolbox, whose `date -s` takes a different format."""
    device = FakeDevice(api=21, toolbox_only=True)
    result = TimeWarpEngine("x", provider=device).fast_forward_time(6, force_jobs=False)
    assert result.ok
    assert result.method == "toolbox"
    assert result.observed_shift_hours == pytest.approx(6.0, abs=0.05)


def test_reported_shift_is_observed_not_requested():
    """A report must never claim a warp the device refused."""
    device = FakeDevice(clock_settable=False, jobs_ok=False)
    result = TimeWarpEngine("x", provider=device).fast_forward_time(24, force_jobs=False)
    assert result.ok is False
    assert result.observed_shift_hours == pytest.approx(0.0, abs=0.01)
    assert any("did not move" in e for e in result.errors)


def test_automatic_time_sync_is_disabled_before_setting_the_clock():
    """An emulator re-syncs within seconds and would silently undo the warp."""
    device = FakeDevice()
    TimeWarpEngine("x", provider=device).fast_forward_time(12, force_jobs=False)
    assert device.auto_time == 0


def test_auto_time_can_be_restored():
    device = FakeDevice()
    engine = TimeWarpEngine("x", provider=device)
    engine.fast_forward_time(12, force_jobs=False)
    engine.restore_auto_time()
    assert device.auto_time == 1


# ── Deferred work ──────────────────────────────────────────────────────────


def test_job_ids_are_scoped_to_the_target_package():
    engine = TimeWarpEngine("x", provider=FakeDevice())
    assert engine.pending_job_ids("com.evil.dropper") == ["12", "77"]
    assert engine.pending_job_ids("com.other.app") == ["5"]
    assert engine.pending_job_ids("com.absent.app") == []
    assert engine.pending_job_ids("") == []


def test_scheduled_jobs_are_forced():
    device = FakeDevice()
    result = TimeWarpEngine("x", provider=device).fast_forward_time(
        24, force_jobs=True, package_name="com.evil.dropper"
    )
    assert result.jobs_forced == ["12", "77"]
    assert any("cmd jobscheduler run -f com.evil.dropper 12" in c for c in device.commands)


def test_doze_is_cycled_to_release_alarm_manager_work():
    """AlarmManager has no 'fire now'; leaving idle flushes deferred work."""
    device = FakeDevice()
    result = TimeWarpEngine("x", provider=device).fast_forward_time(
        24, force_jobs=True, package_name="com.evil.dropper"
    )
    assert result.idle_cycled
    joined = " ".join(device.commands)
    assert "deviceidle force-idle" in joined
    assert "deviceidle unforce" in joined


def test_forcing_jobs_alone_counts_as_success():
    """On a hardened image the clock may be immovable but jobs still respond."""
    device = FakeDevice(clock_settable=False, jobs_ok=True)
    result = TimeWarpEngine("x", provider=device).fast_forward_time(
        24, force_jobs=True, package_name="com.evil.dropper"
    )
    assert result.ok is True
    assert result.jobs_forced
    assert result.errors, "the clock failure is still reported"


def test_missing_package_warns_rather_than_guessing():
    device = FakeDevice()
    result = TimeWarpEngine("x", provider=device).fast_forward_time(24, force_jobs=True)
    assert result.jobs_forced == []
    assert any("No package name" in w for w in result.warnings)


# ── Guardrails ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("hours", [0, -1, -24])
def test_non_positive_warp_is_refused(hours):
    result = TimeWarpEngine("x", provider=FakeDevice()).fast_forward_time(hours)
    assert result.ok is False
    assert result.errors


def test_absurd_warp_is_refused():
    """Jumping years expires TLS certificates and breaks network observation."""
    result = TimeWarpEngine("x", provider=FakeDevice()).fast_forward_time(MAX_WARP_HOURS + 1)
    assert result.ok is False
    assert "Refusing to warp" in result.errors[0]


def test_result_serialises_for_the_api():
    payload = (
        TimeWarpEngine("x", provider=FakeDevice())
        .fast_forward_time(24, True, package_name="com.evil.dropper")
        .to_dict()
    )
    for key in ("ok", "requested_hours", "observed_shift_hours", "method", "jobs_forced"):
        assert key in payload
