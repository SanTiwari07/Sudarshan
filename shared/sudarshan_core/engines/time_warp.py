"""Time Warp - advance the sandbox clock to defeat dormancy timers.

A dropper that waits six hours before fetching its second stage is
indistinguishable, inside a 90-second run, from an app that does nothing. The
telemetry is identical: no network, no hooks, no behaviour. Anatsa built a
business on exactly that gap, and no amount of better observation closes it -
the payload has not run yet.

Three levers, applied together because each alone is defeated by the next:

1. **Wall clock** (``date``) - moves ``System.currentTimeMillis`` so anything
   comparing a stored timestamp against "now" fires. Does not move
   ``SystemClock.elapsedRealtime``, which is monotonic since boot.
2. **JobScheduler / deviceidle** - a ``WorkManager`` job is scheduled against
   the framework's own timers, which the wall clock does not retro-actively
   trigger. The scheduler has to be told to run the job.
3. **Frida offset** (``frida_hooks/time_warp.js``) - for in-process timers that
   read the clock through Java APIs, applied by the sandbox at hook level.

Everything here resolves ADB, the device serial and the API level at runtime;
nothing is pinned to an emulator, an image or an Android release. Where the
correct command differs by API level, the alternatives are attempted in order
and the result is **verified by reading the clock back**, because ``date`` on
Android exits 0 in several cases where it did not actually change anything.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

#: Refuse absurd jumps - a typo of 24000 hours would push the device past
#: certificate validity windows and break TLS on every subsequent request.
MAX_WARP_HOURS = 24 * 90

# `date` accepted these formats at different points in Android's history:
#   toybox  (API 23+): date MMDDhhmm[[CC]YY][.ss]
#   toolbox (API <23): date -s YYYYMMDD.HHmmss
# Newer toybox also accepts an epoch via `date @<seconds>`.
_FMT_TOYBOX = "%m%d%H%M%Y.%S"
_FMT_TOOLBOX = "%Y%m%d.%H%M%S"

_JOB_ID_RE = re.compile(r"#(?:u\d+a\d+)?/?(\d+)\b|JOB #\w+/(\w+)|jobid=(\d+)", re.IGNORECASE)


@dataclass
class TimeWarpResult:
    """Outcome of one time-warp application."""

    requested_hours: float = 0.0
    ok: bool = False
    api_level: int = 0
    clock_before_ms: int = 0
    clock_after_ms: int = 0
    observed_shift_hours: float = 0.0
    method: str = ""
    auto_time_disabled: bool = False
    jobs_forced: List[str] = field(default_factory=list)
    idle_cycled: bool = False
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_hours": self.requested_hours,
            "ok": self.ok,
            "api_level": self.api_level,
            "clock_before_ms": self.clock_before_ms,
            "clock_after_ms": self.clock_after_ms,
            "observed_shift_hours": round(self.observed_shift_hours, 3),
            "method": self.method,
            "auto_time_disabled": self.auto_time_disabled,
            "jobs_forced": list(self.jobs_forced),
            "idle_cycled": self.idle_cycled,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


class TimeWarpEngine:
    """Applies temporal fast-forwarding to one connected sandbox device."""

    def __init__(self, device_serial: str, provider: Optional[Any] = None) -> None:
        self.device_serial = device_serial
        self._provider = provider

    def _get_provider(self):
        if self._provider is not None:
            return self._provider
        from sudarshan_core.sandbox import get_sandbox_provider

        return get_sandbox_provider()

    def _shell(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        try:
            return self._get_provider().adb_shell(
                self.device_serial, command, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("[TimeWarp] shell failed: %s", exc)
            return False, str(exc)

    # ── Probes ─────────────────────────────────────────────────────────────

    def api_level(self) -> int:
        ok, out = self._shell("getprop ro.build.version.sdk", timeout=15)
        if not ok:
            return 0
        try:
            return int((out or "").strip().splitlines()[-1].strip())
        except (ValueError, IndexError):
            return 0

    def device_epoch_ms(self) -> int:
        """Current device wall clock in Unix milliseconds."""
        ok, out = self._shell("date +%s", timeout=15)
        if ok:
            text = (out or "").strip().splitlines()[-1].strip() if out else ""
            if text.isdigit():
                return int(text) * 1000
        return 0

    # ── Clock ──────────────────────────────────────────────────────────────

    def _candidate_commands(self, target: datetime, api: int) -> List[Tuple[str, str]]:
        """``(method_label, command)`` pairs, most-likely-correct first."""
        toybox = f"date {target.strftime(_FMT_TOYBOX)}"
        toolbox = f"date -s {target.strftime(_FMT_TOOLBOX)}"
        epoch = f"date @{int(target.timestamp())}"
        if api and api < 23:
            return [("toolbox", toolbox), ("toybox", toybox), ("epoch", epoch)]
        return [("toybox", toybox), ("epoch", epoch), ("toolbox", toolbox)]

    def set_clock_forward(self, hours: float, result: TimeWarpResult) -> bool:
        """
        Advance the device wall clock by ``hours``, verifying the result.

        Verification is not optional: ``date`` returns success on several
        Android images while leaving the clock untouched (no permission, or an
        argument the applet parsed but ignored). Trusting the exit code here
        produced "time warp applied" in the UI with a device still sitting at
        the original timestamp.
        """
        before = self.device_epoch_ms()
        result.clock_before_ms = before
        if not before:
            result.errors.append("Could not read the device clock; refusing to set it blind.")
            return False

        target = datetime.fromtimestamp(before / 1000, tz=timezone.utc) + timedelta(hours=hours)
        # Automatic time sync will undo the change within seconds on an
        # emulator, so it has to be off before the clock moves - and it is
        # restored by `restore_auto_time()` at the end of the run.
        ok_auto, _ = self._shell("settings put global auto_time 0", timeout=20)
        result.auto_time_disabled = bool(ok_auto)
        if not ok_auto:
            result.warnings.append(
                "Could not disable automatic time sync; the device may revert "
                "the clock while the sample is running."
            )

        tolerance_ms = 5 * 60 * 1000  # generous: command + round-trip latency
        for label, command in self._candidate_commands(target, result.api_level):
            self._shell(command, timeout=25)
            after = self.device_epoch_ms()
            if not after:
                continue
            shift_ms = after - before
            if abs(shift_ms - hours * 3_600_000) <= tolerance_ms:
                result.clock_after_ms = after
                result.observed_shift_hours = shift_ms / 3_600_000
                result.method = label
                logger.info(
                    "[TimeWarp] Clock advanced %.2fh via %s on %s",
                    result.observed_shift_hours,
                    label,
                    self.device_serial,
                )
                return True

        result.clock_after_ms = self.device_epoch_ms()
        result.observed_shift_hours = (result.clock_after_ms - before) / 3_600_000
        result.errors.append(
            "Every `date` variant was accepted but the clock did not move. "
            "The shell likely lacks SET_TIME; use a userdebug image or run "
            "`adb root` first."
        )
        return False

    def restore_auto_time(self) -> bool:
        """Re-enable network time sync. Call once the run is finished."""
        ok, _ = self._shell("settings put global auto_time 1", timeout=20)
        return ok

    # ── Deferred work ──────────────────────────────────────────────────────

    def pending_job_ids(self, package_name: str) -> List[str]:
        """
        Job ids the framework currently holds for ``package_name``.

        Parsed from ``dumpsys jobscheduler`` because there is no stable
        machine-readable listing. The format has changed across releases, so
        several id shapes are matched and the result is de-duplicated.
        """
        if not package_name:
            return []
        ok, out = self._shell("dumpsys jobscheduler", timeout=60)
        if not ok or not out:
            return []

        ids: List[str] = []
        for block in out.split("JOB #")[1:]:
            head = block[:400]
            if package_name not in head:
                continue
            # "JOB #u0a123/45: ..." - the id is after the slash.
            first_line = head.splitlines()[0] if head.splitlines() else ""
            match = re.search(r"/(\d+)\s*:", first_line)
            if match:
                job_id = match.group(1)
                if job_id not in ids:
                    ids.append(job_id)
        return ids

    def force_pending_jobs(self, package_name: str, result: TimeWarpResult) -> List[str]:
        """
        Run the package's scheduled jobs now.

        Moving the wall clock does not retro-actively fire a WorkManager job:
        the scheduler holds its own timers, so a job due in six hours is still
        due in six hours. ``cmd jobscheduler run -f`` is the only supported way
        to make it execute immediately.
        """
        if not package_name:
            result.warnings.append("No package name supplied; cannot force scheduled jobs.")
            return []

        job_ids = self.pending_job_ids(package_name)
        if not job_ids:
            result.warnings.append(
                f"No scheduled jobs found for {package_name}. The sample may use "
                "AlarmManager or an in-process timer instead - the idle cycle "
                "and the Frida clock offset cover those."
            )
            return []

        forced: List[str] = []
        for job_id in job_ids[:20]:
            ok, out = self._shell(
                f"cmd jobscheduler run -f {package_name} {job_id}", timeout=45
            )
            lowered = (out or "").lower()
            if ok and "error" not in lowered and "exception" not in lowered:
                forced.append(job_id)
            else:
                logger.debug("[TimeWarp] job %s not forced: %s", job_id, (out or "")[:160])
        if forced:
            logger.info(
                "[TimeWarp] Forced %d job(s) for %s: %s",
                len(forced),
                package_name,
                ", ".join(forced),
            )
        result.jobs_forced = forced
        return forced

    def cycle_doze(self, result: TimeWarpResult) -> bool:
        """
        Drive the device through a Doze cycle to release deferred work.

        AlarmManager exposes no "fire now" command. What it does have is a
        maintenance window: when the device leaves idle, everything deferred
        during idle is dispatched. Forcing idle and then releasing it is the
        documented way to reach that path, and it is how deferred alarms and
        the WorkManager backlog actually get flushed.
        """
        steps = [
            "dumpsys deviceidle enable",
            "dumpsys deviceidle force-idle",
            "dumpsys deviceidle step",
            "dumpsys deviceidle unforce",
            "dumpsys battery reset",
        ]
        succeeded = 0
        for step in steps:
            ok, _ = self._shell(step, timeout=30)
            if ok:
                succeeded += 1
        cycled = succeeded >= 3
        if not cycled:
            result.warnings.append(
                "Doze cycling was largely rejected; deferred AlarmManager work "
                "may not have been released."
            )
        result.idle_cycled = cycled
        return cycled

    # ── Entry point ────────────────────────────────────────────────────────

    def fast_forward_time(
        self,
        hours: float = 24.0,
        force_jobs: bool = True,
        *,
        package_name: str = "",
    ) -> TimeWarpResult:
        """
        Advance the sandbox clock and release deferred work.

        Returns a :class:`TimeWarpResult` describing what actually happened -
        including the *observed* clock shift, not the requested one, so a
        report never claims a warp the device refused.
        """
        result = TimeWarpResult(requested_hours=float(hours))

        if hours <= 0:
            result.errors.append("Warp must be a positive number of hours.")
            return result
        if hours > MAX_WARP_HOURS:
            result.errors.append(
                f"Refusing to warp {hours}h; the maximum is {MAX_WARP_HOURS}h. "
                "Jumps beyond that expire TLS certificates and break every "
                "subsequent network observation."
            )
            return result

        result.api_level = self.api_level()
        clock_ok = self.set_clock_forward(hours, result)

        if force_jobs:
            self.force_pending_jobs(package_name, result)
            self.cycle_doze(result)

        # A run counts as successful if *either* lever moved: on a hardened
        # image the clock may be immovable while the job scheduler still
        # responds, and forcing the job is the outcome that matters.
        result.ok = clock_ok or bool(result.jobs_forced)
        return result
