"""Autonomous anti-evasion - time warp and synthetic persona, in one pass.

The two dormancy defences already live here separately:
:mod:`sudarshan_core.engines.time_warp` moves the clock and releases deferred
work, :mod:`sudarshan_core.engines.device_state_simulator` fills the device with
a history. Applied one at a time, from separate buttons, they are easy to
misread - a sample that unpacks only when *both* a stale timer has elapsed
*and* the address book is populated stays dormant through either control on its
own, and the analyst concludes it is inert.

This module drives both as one sequence and, crucially, brackets it with a
before/after behaviour snapshot so the panel can answer the only question that
matters: **did the sample do anything it was not doing a minute ago?**

Truth rules, which the rest of this file exists to enforce:

* A metric that could not be read is ``None``, never ``0``. "Zero SMS reads"
  and "we could not see SMS reads" are different claims and only one of them
  is usually true.
* ``NO_CHANGES_OBSERVED`` is only reachable when the hook stream was actually
  attached. Without instrumentation the run produces
  ``NO_RUNTIME_TELEMETRY``: it observed nothing because it was not observing,
  which is not evidence about the sample. This is the same principle
  :mod:`sudarshan_core.engines.execution_assertions` applies to a whole run.
* Deltas that any app produces - an outbound TCP connection - are reported as
  context and never on their own promote the verdict. Detonation is claimed
  from threat-class signals only.

Nothing here is pinned to an emulator, an image or an Android release: the
device serial, API level and app uid are all resolved at runtime, and every
probe degrades to "unavailable" rather than to a convenient zero.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

#: Clock offsets, in hours from the original device time, applied in order.
#: Three shifts rather than one jump: a sample that samples the clock while it
#: is running sees time *passing*, and each shift is paired with a different
#: framework lever (job flush, Doze entry, Doze exit).
DEFAULT_WARP_SCHEDULE: Tuple[float, float, float] = (6.0, 12.0, 24.0)

#: How long to let the instrumented process run before the closing snapshot.
DEFAULT_OBSERVATION_SECONDS = 3.0

#: Persona volume for the seeding steps. Deliberately small - the point is to
#: clear an emptiness check inside a live session, not to furnish the device.
DEFAULT_CONTACT_COUNT = 12
DEFAULT_SMS_COUNT = 4
DEFAULT_CALL_COUNT = 10
DEFAULT_PHOTO_COUNT = 3

# Android framework constants, mirroring device_state_simulator.
_URI_SMS_INBOX = "content://sms/inbox"
_URI_CALL_LOG = "content://call_log/calls"
_DCIM_DIR = "/sdcard/DCIM/Camera"

VERDICT_DETONATED = "MALWARE_DETONATED"
VERDICT_NO_CHANGES = "NO_CHANGES_OBSERVED"
VERDICT_NO_TELEMETRY = "NO_RUNTIME_TELEMETRY"

# Frida hook categories (see FridaSession.collected_events) mapped onto the
# metrics an analyst reads. The mapping is here rather than in the API layer so
# a renamed hook category breaks one line, not the contract.
_HOOK_CATEGORY_FOR_METRIC = {
    "sms_reads": "sms",
    "c2_requests": "network",
    "accessibility_events": "accessibility",
    "overlay_events": "overlay",
}


@dataclass(frozen=True)
class MetricSpec:
    """One row of the delta table."""

    key: str
    label: str
    #: Threat-class metrics can promote the verdict to detonated. Context
    #: metrics are reported and never scored - every app opens sockets.
    threat_class: bool
    source: str
    #: What a non-zero delta actually licenses the analyst to say.
    meaning: str


METRICS: Tuple[MetricSpec, ...] = (
    MetricSpec(
        "sms_reads",
        "SMS provider reads / interception hooks",
        True,
        "frida",
        "The sample touched the message store after the inbox was seeded.",
    ),
    MetricSpec(
        "c2_requests",
        "Outbound network calls (C2 candidates)",
        True,
        "frida",
        "The sample made network calls it was not making before the warp.",
    ),
    MetricSpec(
        "accessibility_events",
        "Accessibility scraping hooks",
        True,
        "frida",
        "The sample read screen content through the accessibility APIs.",
    ),
    MetricSpec(
        "overlay_events",
        "Overlay draw hooks (addView / TYPE_APPLICATION_OVERLAY)",
        True,
        "frida",
        "The sample drew a window over another app's surface.",
    ),
    MetricSpec(
        "overlay_windows",
        "Overlay windows held by the package",
        True,
        "device",
        "The window manager is holding an overlay owned by the sample.",
    ),
    MetricSpec(
        "accessibility_service_bound",
        "Accessibility service bound to the sample",
        True,
        "device",
        "The sample's accessibility service became bound during the sequence.",
    ),
    MetricSpec(
        "network_connections",
        "Established TCP connections owned by the app uid",
        False,
        "device",
        "Context only - a connection count says nothing about intent.",
    ),
)

_METRIC_BY_KEY = {m.key: m for m in METRICS}


# ── Results ────────────────────────────────────────────────────────────────


@dataclass
class StepResult:
    """What one step of the sequence actually did on the device."""

    key: str
    label: str
    ok: bool = False
    detail: str = ""
    duration_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "ok": self.ok,
            "detail": self.detail,
            "duration_ms": round(self.duration_ms, 1),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "data": dict(self.data),
        }


@dataclass
class BehaviorSnapshot:
    """Behaviour counters at one instant. ``None`` means *not observable*."""

    captured_at: float = 0.0
    hooks_attached: bool = False
    telemetry_source: str = ""
    metrics: Dict[str, Optional[int]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "hooks_attached": self.hooks_attached,
            "telemetry_source": self.telemetry_source,
            "metrics": dict(self.metrics),
            "notes": list(self.notes),
        }


@dataclass
class MetricDelta:
    """One before/after comparison, with its provenance."""

    key: str
    label: str
    before: Optional[int]
    after: Optional[int]
    delta: Optional[int]
    observable: bool
    threat_class: bool
    source: str
    meaning: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "before": self.before,
            "after": self.after,
            "delta": self.delta,
            "observable": self.observable,
            "threat_class": self.threat_class,
            "source": self.source,
            "meaning": self.meaning,
        }


@dataclass
class AppliedChanges:
    """
    What the sequence physically did to the device.

    Separate from the behaviour verdict on purpose. "The clock is now 18:04 and
    the inbox holds four bank alerts" is a fact about the sandbox that is true
    whether or not the sample reacted, and an analyst who cannot see it has no
    way to tell a working control from a silent no-op. The verdict answers a
    different question - what the *sample* did about it.
    """

    clock_before_ms: int = 0
    clock_after_ms: int = 0
    clock_shift_hours: float = 0.0
    jobs_forced: int = 0
    doze_cycled: bool = False
    battery_level: Optional[int] = None
    #: Rows this run wrote, by provider.
    seeded: Dict[str, int] = field(default_factory=dict)
    #: Rows the device already carried, so the write was skipped.
    already_present: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clock_before_ms": self.clock_before_ms,
            "clock_after_ms": self.clock_after_ms,
            "clock_shift_hours": round(self.clock_shift_hours, 2),
            "jobs_forced": self.jobs_forced,
            "doze_cycled": self.doze_cycled,
            "battery_level": self.battery_level,
            "seeded": dict(self.seeded),
            "already_present": dict(self.already_present),
        }


def summarise_applied_changes(steps: Sequence[StepResult]) -> AppliedChanges:
    """Fold the step results into one description of the device's new state."""
    applied = AppliedChanges()
    for step in steps:
        data = step.data or {}
        if step.key.startswith("warp_"):
            warp = data.get("time_warp") or {}
            before = int(warp.get("clock_before_ms") or 0)
            after = int(warp.get("clock_after_ms") or 0)
            # First reading wins for "before", last for "after": the shifts are
            # cumulative and the analyst wants the ends, not the middle.
            if before and not applied.clock_before_ms:
                applied.clock_before_ms = before
            if after:
                applied.clock_after_ms = after
            applied.clock_shift_hours += float(warp.get("observed_shift_hours") or 0.0)
            applied.jobs_forced += len(warp.get("jobs_forced") or [])
            applied.doze_cycled = applied.doze_cycled or bool(
                warp.get("idle_cycled") or data.get("doze_forced") or data.get("doze_released")
            )
        elif step.key == "battery":
            applied.battery_level = data.get("observed_level")
        elif step.key in ("contacts", "calls", "sms", "photos"):
            inserted = int(data.get("inserted") or 0)
            present = int(data.get("already_present") or 0)
            if inserted:
                applied.seeded[step.key] = inserted
            if present:
                applied.already_present[step.key] = present
    return applied


@dataclass
class AntiEvasionResult:
    """Everything the panel needs, and nothing it has to infer."""

    session_id: str = ""
    device_serial: str = ""
    package_name: str = ""
    persona_id: str = ""
    verdict: str = VERDICT_NO_TELEMETRY
    summary: str = ""
    ok: bool = False
    steps: List[StepResult] = field(default_factory=list)
    deltas: List[MetricDelta] = field(default_factory=list)
    before: Optional[BehaviorSnapshot] = None
    after: Optional[BehaviorSnapshot] = None
    applied_changes: Optional[AppliedChanges] = None
    triggered_keys: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: float = 0.0
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "device_serial": self.device_serial,
            "package_name": self.package_name,
            "persona_id": self.persona_id,
            "verdict": self.verdict,
            "summary": self.summary,
            "ok": self.ok,
            "steps": [s.to_dict() for s in self.steps],
            "deltas": [d.to_dict() for d in self.deltas],
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "applied_changes": (
                self.applied_changes.to_dict() if self.applied_changes else None
            ),
            "triggered_keys": list(self.triggered_keys),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class Step:
    """A named unit of device work the caller drives, so it can report progress."""

    key: str
    label: str
    description: str
    run: Callable[[], StepResult]


#: Supplies live hook-telemetry counts. Injected by the API layer because the
#: telemetry buffer belongs to the process hosting the HTTP gateway, and
#: nothing in ``sudarshan_core`` may import upwards into it.
#:
#: Returns ``{"attached": bool, "source": str, "counts": {category: int}}``.
TelemetryProbe = Callable[[], Dict[str, Any]]


# ── Orchestrator ───────────────────────────────────────────────────────────


class AntiEvasionOrchestrator:
    """
    Runs the time-warp / persona sequence against one device and measures it.

    Two ways in. :meth:`run_sequence` executes the whole thing and is what the
    sandbox calls mid-session, where there is no UI to drive. The API layer
    instead drives :meth:`steps` one at a time so a panel can show each step as
    it happens - a fifteen-second silent spinner over a live sandbox is exactly
    the experience these controls exist to replace. Both paths share the same
    step implementations and the same verdict logic.
    """

    def __init__(
        self,
        device_serial: str,
        package_name: str = "",
        *,
        persona_id: str = "default_retail_user",
        warp_schedule: Sequence[float] = DEFAULT_WARP_SCHEDULE,
        contact_count: int = DEFAULT_CONTACT_COUNT,
        sms_count: int = DEFAULT_SMS_COUNT,
        call_count: int = DEFAULT_CALL_COUNT,
        photo_count: int = DEFAULT_PHOTO_COUNT,
        battery_level: int = 50,
        telemetry_probe: Optional[TelemetryProbe] = None,
        provider: Optional[Any] = None,
    ) -> None:
        self.device_serial = device_serial
        self.package_name = (package_name or "").strip()
        self.persona_id = persona_id
        self.warp_schedule = tuple(float(h) for h in warp_schedule if float(h) > 0)
        self.contact_count = max(0, int(contact_count))
        self.sms_count = max(0, int(sms_count))
        self.call_count = max(0, int(call_count))
        self.photo_count = max(0, int(photo_count))
        self.battery_level = max(1, min(int(battery_level), 100))
        self._telemetry_probe = telemetry_probe
        self._provider = provider
        self._app_uid: Optional[int] = None
        self._uid_resolved = False
        #: Device wall clock before the first shift, so the sequence can put it
        #: back. Left as None when no warp was applied - restoring a clock that
        #: was never moved would introduce the drift it exists to prevent.
        self._clock_before_warp_ms: Optional[int] = None
        self._battery_overridden = False

    # ── Device access ──────────────────────────────────────────────────────

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
            logger.debug("[AntiEvasion] shell failed: %s", exc)
            return False, str(exc)

    # ── Device-side probes ─────────────────────────────────────────────────
    #
    # These exist so the sequence still measures *something* on a device with
    # no Frida attached. They observe the framework's own bookkeeping - which
    # windows exist, which services are bound, which sockets are open - and
    # each returns None when the dump cannot be read, never a zero.

    def _app_uid_value(self) -> Optional[int]:
        """Linux uid of the target package, resolved once per orchestrator."""
        if self._uid_resolved:
            return self._app_uid
        self._uid_resolved = True
        if not self.package_name:
            return None

        ok, out = self._shell(f"cmd package list packages -U {self.package_name}", timeout=20)
        match = re.search(r"uid:(\d+)", out or "") if ok else None
        if not match:
            # Older images have no `-U` flag on the package shell command.
            ok, out = self._shell(f"dumpsys package {self.package_name}", timeout=45)
            match = re.search(r"\buserId=(\d+)", out or "") if ok else None
        if match:
            self._app_uid = int(match.group(1))
        return self._app_uid

    def overlay_window_count(self) -> Optional[int]:
        """
        Overlay windows the window manager currently holds for the package.

        Counted from ``dumpsys window windows``: each window is a block, the
        owner appears in its header, and the type is reported as ``ty=``. Both
        the modern ``APPLICATION_OVERLAY`` and the pre-Oreo ``SYSTEM_ALERT``
        spellings are matched, plus the raw numeric types some builds print.
        """
        if not self.package_name:
            return None
        ok, out = self._shell("dumpsys window windows", timeout=45)
        if not ok or not out:
            return None

        overlay_marker = re.compile(
            r"ty=(?:TYPE_)?(?:APPLICATION_OVERLAY|SYSTEM_ALERT|SYSTEM_OVERLAY|PHONE|2038|2003|2002)",
            re.IGNORECASE,
        )
        count = 0
        for block in out.split("Window #")[1:]:
            if self.package_name not in block:
                continue
            if overlay_marker.search(block):
                count += 1
        return count

    def accessibility_service_bound(self) -> Optional[int]:
        """1 when an accessibility service owned by the package is bound."""
        if not self.package_name:
            return None

        ok, out = self._shell("dumpsys accessibility", timeout=45)
        if ok and out:
            for line in out.splitlines():
                if "bound services" in line.lower() or "enabled services" in line.lower():
                    if self.package_name in line:
                        return 1
            # The dump was readable and did not name the package.
            bound: Optional[int] = 0
        else:
            bound = None

        # Secondary read: the setting survives dump-format changes and is what
        # the framework consults when binding.
        ok2, out2 = self._shell(
            "settings get secure enabled_accessibility_services", timeout=20
        )
        if ok2 and out2 and self.package_name in out2:
            return 1
        return bound

    def established_connection_count(self) -> Optional[int]:
        """
        Established, non-loopback TCP connections owned by the app uid.

        Context only. It is here because a dropper waking up to fetch stage two
        is visible in the socket table even when no hook is attached - but so
        is any app checking for updates, which is why this never promotes a
        verdict on its own.
        """
        uid = self._app_uid_value()
        if uid is None:
            return None
        ok, out = self._shell("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null", timeout=25)
        if not ok or not out or "local_address" not in out:
            # Android restricts /proc/net for apps on newer releases; the adb
            # shell usually still reads it, but when it cannot, say so.
            return None

        count = 0
        for line in out.splitlines():
            fields = line.split()
            if len(fields) < 8 or ":" not in fields[1]:
                continue
            state, row_uid = fields[3], fields[7]
            if state != "01" or not row_uid.isdigit() or int(row_uid) != uid:
                continue
            remote_hex = fields[2].split(":")[0]
            if _is_local_address(remote_hex):
                continue
            count += 1
        return count

    # ── Snapshots ──────────────────────────────────────────────────────────

    def snapshot(self) -> BehaviorSnapshot:
        """Read every metric once. Unreadable metrics come back as ``None``."""
        snap = BehaviorSnapshot(captured_at=time.time())

        telemetry: Dict[str, Any] = {}
        if self._telemetry_probe is not None:
            try:
                telemetry = self._telemetry_probe() or {}
            except Exception as exc:  # noqa: BLE001
                logger.debug("[AntiEvasion] telemetry probe failed: %s", exc)
                snap.notes.append(f"Hook telemetry probe failed: {exc}")

        snap.hooks_attached = bool(telemetry.get("attached"))
        snap.telemetry_source = str(telemetry.get("source") or "")
        counts = telemetry.get("counts") or {}

        for metric, category in _HOOK_CATEGORY_FOR_METRIC.items():
            if not snap.hooks_attached:
                snap.metrics[metric] = None
                continue
            value = counts.get(category)
            snap.metrics[metric] = int(value) if isinstance(value, (int, float)) else 0

        snap.metrics["overlay_windows"] = self.overlay_window_count()
        snap.metrics["accessibility_service_bound"] = self.accessibility_service_bound()
        snap.metrics["network_connections"] = self.established_connection_count()

        if not snap.hooks_attached:
            snap.notes.append(
                "No Frida hook stream is attached to this session, so API-level "
                "behaviour (SMS reads, C2 calls, accessibility scraping) is not "
                "observable in this window."
            )
        if not self.package_name:
            snap.notes.append(
                "No package name was supplied, so device-side window, "
                "accessibility and socket checks could not be attributed."
            )
        return snap

    # ── Steps ──────────────────────────────────────────────────────────────

    def steps(self) -> List[Step]:
        """The device sequence, in execution order."""
        plan: List[Step] = []

        previous = 0.0
        levers = ("flush scheduled jobs", "enter Doze", "leave Doze")
        for index, offset in enumerate(self.warp_schedule):
            increment = offset - previous
            previous = offset
            if increment <= 0:
                continue
            lever = levers[index] if index < len(levers) else "release deferred work"
            plan.append(
                Step(
                    key=f"warp_{int(offset)}h",
                    label=f"Fast-forward clock to +{offset:g}h",
                    description=f"Advance the device clock and {lever}.",
                    run=lambda hours=increment, total=offset, stage=index: self._warp(
                        hours, total, stage
                    ),
                )
            )

        plan.append(
            Step(
                key="battery",
                label=f"Inject battery telemetry ({self.battery_level}%, discharging)",
                description="A permanently 100%-charged, always-plugged device is a sandbox tell.",
                run=self._seed_battery,
            )
        )
        if self.contact_count:
            plan.append(
                Step(
                    key="contacts",
                    label=f"Seed {self.contact_count} contacts",
                    description="Clears the empty-address-book emptiness check.",
                    run=self._seed_contacts,
                )
            )
        if self.call_count:
            plan.append(
                Step(
                    key="calls",
                    label=f"Seed {self.call_count} call-log entries",
                    description="A device nobody has ever called is a device nobody uses.",
                    run=self._seed_calls,
                )
            )
        if self.sms_count:
            plan.append(
                Step(
                    key="sms",
                    label=f"Seed {self.sms_count} bank SMS",
                    description="Gives interception hooks something to intercept.",
                    run=self._seed_sms,
                )
            )
        if self.photo_count:
            plan.append(
                Step(
                    key="photos",
                    label=f"Seed {self.photo_count} camera-roll photos",
                    description="An empty gallery is one more emptiness check to fail.",
                    run=self._seed_photos,
                )
            )
        return plan

    def _warp(self, increment_hours: float, total_offset: float, stage: int) -> StepResult:
        """One clock shift plus the framework lever paired with it."""
        from sudarshan_core.engines.time_warp import TimeWarpEngine

        step = StepResult(
            key=f"warp_{int(total_offset)}h",
            label=f"Fast-forward clock to +{total_offset:g}h",
        )
        engine = TimeWarpEngine(self.device_serial, provider=self._get_provider())

        # Only the first shift pays for a `dumpsys jobscheduler` sweep. The
        # later shifts drive Doze directly, which is what actually releases
        # AlarmManager work, and re-dumping the scheduler twice more would cost
        # most of the sequence's time budget for no new information.
        force_jobs = stage == 0
        warp = engine.fast_forward_time(
            increment_hours, force_jobs, package_name=self.package_name
        )
        if self._clock_before_warp_ms is None and warp.clock_before_ms:
            self._clock_before_warp_ms = warp.clock_before_ms
        step.warnings.extend(warp.warnings)
        step.errors.extend(warp.errors)
        step.data["time_warp"] = warp.to_dict()

        idle_detail = ""
        if stage == 1:
            # Entering idle is what defers the work; the sample's alarms pile up.
            ok_enable, _ = self._shell("dumpsys deviceidle enable", timeout=30)
            ok_idle, _ = self._shell("dumpsys deviceidle force-idle", timeout=30)
            step.data["doze_forced"] = bool(ok_enable and ok_idle)
            idle_detail = "Doze forced" if ok_enable and ok_idle else "Doze entry refused"
            if not (ok_enable and ok_idle):
                step.warnings.append(
                    "The device refused to enter Doze; deferred alarms may not "
                    "have queued for the maintenance window."
                )
        elif stage >= 2:
            # Leaving idle opens the maintenance window, and everything the
            # device deferred is dispatched at once.
            self._shell("dumpsys deviceidle step", timeout=30)
            ok_unforce, _ = self._shell("dumpsys deviceidle unforce", timeout=30)
            step.data["doze_released"] = bool(ok_unforce)
            idle_detail = "Doze released" if ok_unforce else "Doze release refused"
            if not ok_unforce:
                step.warnings.append("The device refused to leave Doze.")

        step.ok = warp.ok
        observed = f"clock moved {warp.observed_shift_hours:+.2f}h"
        if not warp.ok:
            observed = "clock did not move"
        parts = [observed]
        if force_jobs:
            parts.append(f"{len(warp.jobs_forced)} job(s) forced")
        if idle_detail:
            parts.append(idle_detail)
        step.detail = ", ".join(parts)
        return step

    def _seed_battery(self) -> StepResult:
        """
        Pin the battery to a plausible discharging level, and verify the read-back.

        Ordering matters: ``TimeWarpEngine.cycle_doze`` finishes with
        ``dumpsys battery reset``, so seeding the battery before the warps
        would silently undo this. It runs after them for that reason.
        """
        step = StepResult(key="battery", label="Inject battery telemetry")
        self._shell(f"dumpsys battery set level {self.battery_level}", timeout=25)
        self._shell("dumpsys battery unplug", timeout=25)
        # `unplug` is absent on some images; setting the status directly is the
        # portable spelling of "discharging" (BatteryManager.STATUS_DISCHARGING).
        self._shell("dumpsys battery set status 3", timeout=25)

        ok, out = self._shell("dumpsys battery", timeout=25)
        level = _first_int(r"^\s*level:\s*(\d+)", out) if ok else None
        status = _first_int(r"^\s*status:\s*(\d+)", out) if ok else None
        ac = re.search(r"AC powered:\s*(\w+)", out or "", re.IGNORECASE)

        step.data = {
            "requested_level": self.battery_level,
            "observed_level": level,
            "observed_status": status,
            "ac_powered": (ac.group(1).lower() == "true") if ac else None,
        }
        step.ok = level == self.battery_level
        if step.ok:
            self._battery_overridden = True
            step.detail = f"battery reads {level}%" + (
                ", discharging" if status == 3 else ""
            )
            step.warnings.append(
                "Battery state stays overridden until `dumpsys battery reset` "
                "is run on the device."
            )
        elif level is None:
            step.detail = "battery state could not be read back"
            step.errors.append("`dumpsys battery` was not readable; injection unverified.")
        else:
            step.detail = f"requested {self.battery_level}%, device reports {level}%"
            step.errors.append("The device did not accept the battery override.")
        return step

    def _seed_contacts(self) -> StepResult:
        """
        Seed the address book, unless this device already carries one.

        The sequence now runs on every dynamic analysis, and a sandbox that is
        not re-imaged between runs would otherwise accumulate a dozen more
        contacts each time. The rows are tagged with the persona account type,
        so an already-furnished device is detectable and the write is skipped -
        the emptiness check is cleared either way, which is the point.
        """
        existing = self._persona_contact_count()
        if existing is not None and existing >= self.contact_count:
            return StepResult(
                key="contacts",
                label="Seed contacts",
                ok=True,
                detail=f"device already carries {existing} persona contact(s); no rows added",
                data={"inserted": 0, "already_present": existing},
            )
        return self._seed("contacts", "Seed contacts", "contacts", "contacts_inserted")

    def _persona_contact_count(self) -> Optional[int]:
        """
        How many raw contacts a previous seed left on this device.

        The where clause has to survive the *device's* shell, which word-splits
        whatever ``adb shell`` hands it. Quoting it by hand produced
        ``'account_type='com.sudarshan.persona''`` - three tokens, no match, and
        a re-seed on every run that took 39s to discover it had nothing to do.
        """
        from sudarshan_core.engines.device_state_simulator import sh_quote

        where = sh_quote("account_type='com.sudarshan.persona'")
        ok, out = self._shell(
            "content query --uri content://com.android.contacts/raw_contacts "
            f"--projection _id --where {where}",
            timeout=45,
        )
        if not ok or out is None:
            return None
        return sum(1 for line in out.splitlines() if "_id=" in line)

    def _seed_calls(self) -> StepResult:
        """Seed the call log, unless the device already has one."""
        existing = self._row_count(_URI_CALL_LOG)
        if existing is not None and existing >= self.call_count:
            return StepResult(
                key="calls",
                label="Seed call-log entries",
                ok=True,
                detail=f"device already holds {existing} call-log entry(ies); no rows added",
                data={"inserted": 0, "already_present": existing},
            )
        return self._seed("calls", "Seed call-log entries", "calls", "calls_inserted")

    def _seed_photos(self) -> StepResult:
        """Seed the camera roll, unless it already has images in it."""
        existing = self._camera_roll_count()
        if existing is not None and existing >= self.photo_count:
            return StepResult(
                key="photos",
                label="Seed camera-roll photos",
                ok=True,
                detail=f"camera roll already holds {existing} image(s); none written",
                data={"inserted": 0, "already_present": existing},
            )
        return self._seed("photos", "Seed camera-roll photos", "photos", "photos_pushed")

    def _row_count(self, uri: str) -> Optional[int]:
        """Rows a provider currently holds, or None when it will not say."""
        ok, out = self._shell(
            f"content query --uri {uri} --projection _id", timeout=45
        )
        if not ok or out is None:
            return None
        return sum(1 for line in out.splitlines() if "_id=" in line)

    def _camera_roll_count(self) -> Optional[int]:
        """Images already in the camera roll directory."""
        ok, out = self._shell(f"ls {_DCIM_DIR} 2>/dev/null | wc -l", timeout=25)
        if not ok or not out:
            return None
        text = out.strip().splitlines()[-1].strip() if out.strip() else ""
        return int(text) if text.isdigit() else None

    def _seed_sms(self) -> StepResult:
        """Seed bank SMS, unless this device already holds the same messages."""
        persona = self._trimmed_persona()
        addresses = {m.address for m in persona.messages} if persona else set()
        existing = self._seeded_sms_count(addresses)
        if existing is not None and addresses and existing >= len(addresses):
            return StepResult(
                key="sms",
                label="Seed bank SMS",
                ok=True,
                detail=f"inbox already holds {existing} message(s) from these senders",
                data={"inserted": 0, "already_present": existing},
            )
        return self._seed("sms", "Seed bank SMS", "messages", "messages_inserted")

    def _seeded_sms_count(self, addresses: Any) -> Optional[int]:
        """
        How many messages from the persona's senders the inbox already holds.

        Same reason as the contact check: the sequence runs on every dynamic
        analysis, and a sandbox that is not re-imaged between samples would
        collect four more bank alerts each time.
        """
        if not addresses:
            return None
        ok, out = self._shell(
            f"content query --uri {_URI_SMS_INBOX} --projection address", timeout=45
        )
        if not ok or out is None:
            return None
        seen = set()
        for line in out.splitlines():
            if "address=" not in line:
                continue
            value = line.split("address=", 1)[1].split(",")[0].strip()
            if value in addresses:
                seen.add(value)
        return len(seen)

    def _seed(self, key: str, label: str, provider: str, count_attr: str) -> StepResult:
        """Write one slice of the persona, reporting rows the device accepted."""
        from sudarshan_core.engines.device_state_simulator import DeviceStateSimulator

        step = StepResult(key=key, label=label)
        persona = self._trimmed_persona()
        if persona is None:
            step.errors.append(f"No persona template matching {self.persona_id!r}")
            step.detail = "persona template missing"
            return step

        simulator = DeviceStateSimulator(self.device_serial, provider=self._get_provider())
        seeded = simulator.seed_persona(
            self.persona_id, persona=persona, include=[provider]
        )
        inserted = int(getattr(seeded, count_attr, 0) or 0)
        step.warnings.extend(seeded.warnings)
        # seed_persona reports "no provider accepted a write" as an error, which
        # is accurate for a whole-persona seed but is the same fact as the count
        # for a single-provider one. Kept once, on the count.
        step.data = {"inserted": inserted, "seed_result": seeded.to_dict()}
        step.ok = inserted > 0
        step.detail = (
            f"{inserted} row(s) accepted by the device"
            if inserted
            else f"the {provider} provider refused every insert"
        )
        if not inserted:
            step.errors.append(
                f"No {provider} rows were written; the emptiness check this step "
                "targets is still unmet."
            )
        return step

    def _trimmed_persona(self):
        """
        The persona, cut down to the rows this sequence seeds.

        Reuses the template rather than inventing rows here: expansion,
        device-shell quoting and the raw-contact/data-row split all already
        live in the persona and simulator modules, and a second copy of them
        would be a second thing to get wrong.
        """
        from sudarshan_core.engines.persona import load_persona

        loaded = load_persona(self.persona_id)
        if loaded is None:
            return None

        # Transactional senders first: an alphabetic sender id (AD-SBIINB) is a
        # DLT header, i.e. a bank or service alert, which is what an evasive
        # sample reads the inbox to find. Personal numbers fill any shortfall.
        sender_id = [m for m in loaded.messages if _is_sender_id(m.address)]
        personal = [m for m in loaded.messages if not _is_sender_id(m.address)]
        messages = (sender_id + personal)[: self.sms_count]

        return replace(
            loaded,
            contacts=list(loaded.contacts[: self.contact_count]),
            messages=messages,
            calls=list(loaded.calls[: self.call_count]),
            photos=list(loaded.photos[: self.photo_count]),
        )

    def restore(self) -> StepResult:
        """
        Put the device back: clock, time sync, battery.

        Not cosmetic. The sequence runs on every dynamic analysis now, so a
        sandbox that is never re-imaged would drift 24h further ahead per
        sample until certificate validity windows expire and every subsequent
        network observation fails - the exact failure ``time_warp`` refuses a
        90-day jump to avoid. The seeded contacts and messages are deliberately
        left in place: they are what the next run wants to find.
        """
        from sudarshan_core.engines.time_warp import TimeWarpEngine, TimeWarpResult

        step = StepResult(key="restore", label="Restore device clock and battery")
        engine = TimeWarpEngine(self.device_serial, provider=self._get_provider())
        done: List[str] = []

        if self._clock_before_warp_ms is not None:
            offset = self.warp_schedule[-1] if self.warp_schedule else 0.0
            if offset:
                # set_clock_forward verifies the read-back, and a negative shift
                # is just as verifiable as a positive one. The few seconds the
                # sequence itself took are far inside its tolerance.
                rewound = TimeWarpResult(requested_hours=-offset)
                rewound.api_level = engine.api_level()
                if engine.set_clock_forward(-offset, rewound):
                    done.append(f"clock rewound {offset:g}h")
                else:
                    step.warnings.append(
                        "The device clock could not be rewound; it is still "
                        f"{offset:g}h ahead. Reset the sandbox before relying on "
                        "TLS-sensitive observations."
                    )
        if engine.restore_auto_time():
            done.append("automatic time sync re-enabled")
        else:
            step.warnings.append("Automatic time sync could not be re-enabled.")

        if self._battery_overridden:
            ok, _ = self._shell("dumpsys battery reset", timeout=25)
            if ok:
                done.append("battery released")
            else:
                step.warnings.append("The battery override could not be released.")

        step.ok = bool(done)
        step.detail = ", ".join(done) if done else "nothing needed restoring"
        return step

    def observation_step(self, seconds: float) -> StepResult:
        """Record the sampling window the caller held open before re-reading."""
        return StepResult(
            key="observe",
            label="Sample the runtime hook stream",
            ok=True,
            detail=f"watched the instrumented process for {seconds:.1f}s",
            duration_ms=seconds * 1000.0,
        )

    # ── Whole sequence ─────────────────────────────────────────────────────

    def run_sequence(
        self,
        *,
        observation_seconds: float = DEFAULT_OBSERVATION_SECONDS,
        session_id: str = "",
        restore: bool = True,
        on_step: Optional[Callable[[StepResult], None]] = None,
    ) -> AntiEvasionResult:
        """
        Snapshot, apply everything, sample, snapshot again, and put the device back.

        This is the mid-session path: the sandbox calls it while the sample is
        running and its hooks are installed, which is the only moment the delta
        can mean anything. Called after the run, with the process gone and the
        hooks unloaded, the same sequence can only ever return
        ``NO_RUNTIME_TELEMETRY``.

        A step that raises is recorded as a failed step rather than aborting the
        sequence: a refused SMS insert must not cost the analyst the time warp
        that came before it.
        """
        started_at = time.time()
        before = self.snapshot()
        results: List[StepResult] = []

        for step in self.steps():
            step_start = time.perf_counter()
            try:
                outcome = step.run()
            except Exception as exc:  # noqa: BLE001
                logger.warning("[AntiEvasion] step %s failed: %s", step.key, exc)
                outcome = StepResult(
                    key=step.key,
                    label=step.label,
                    ok=False,
                    detail=f"step raised {type(exc).__name__}",
                    errors=[str(exc)],
                )
            outcome.duration_ms = (time.perf_counter() - step_start) * 1000.0
            results.append(outcome)
            if on_step is not None:
                try:
                    on_step(outcome)
                except Exception:  # noqa: BLE001
                    logger.debug("[AntiEvasion] step callback failed", exc_info=True)

        if observation_seconds > 0:
            time.sleep(observation_seconds)
        results.append(self.observation_step(observation_seconds))

        after = self.snapshot()
        if restore:
            # After the closing snapshot: rewinding the clock first would let
            # the sample observe time going backwards inside the window we are
            # measuring.
            restore_start = time.perf_counter()
            restored = self.restore()
            restored.duration_ms = (time.perf_counter() - restore_start) * 1000.0
            results.append(restored)

        return self.summarise(
            before, after, results, session_id=session_id, started_at=started_at
        )

    # ── Verdict ────────────────────────────────────────────────────────────

    def summarise(
        self,
        before: BehaviorSnapshot,
        after: BehaviorSnapshot,
        steps: Sequence[StepResult],
        *,
        session_id: str = "",
        started_at: float = 0.0,
    ) -> AntiEvasionResult:
        """Compare the snapshots and say only what the comparison supports."""
        result = AntiEvasionResult(
            session_id=session_id,
            device_serial=self.device_serial,
            package_name=self.package_name,
            persona_id=self.persona_id,
            steps=list(steps),
            before=before,
            after=after,
            started_at=started_at or before.captured_at,
        )
        result.duration_seconds = max(0.0, after.captured_at - result.started_at)
        result.deltas = compute_deltas(before, after)
        result.applied_changes = summarise_applied_changes(steps)

        for step in steps:
            result.warnings.extend(step.warnings)
            result.errors.extend(step.errors)

        triggered = [
            d for d in result.deltas if d.threat_class and (d.delta or 0) > 0
        ]
        result.triggered_keys = [d.key for d in triggered]
        # "Applied" means the device accepted the manipulation, not that the
        # request was sent. A sequence the device refused outright cannot
        # support a benign reading either.
        applied = [s for s in steps if s.ok and s.key not in ("observe", "restore")]
        result.ok = bool(applied)

        if triggered:
            result.verdict = VERDICT_DETONATED
            result.summary = _detonation_summary(triggered, self.warp_schedule)
            return result

        hook_metrics_observable = any(
            d.observable for d in result.deltas if d.source == "frida"
        )
        if not hook_metrics_observable:
            result.verdict = VERDICT_NO_TELEMETRY
            result.summary = (
                "The device manipulations were applied, but no Frida hook stream "
                "was attached to this session, so API-level behaviour was never "
                "observed. This run says nothing about the sample either way - "
                "re-run the anti-evasion sequence during a live instrumented "
                "session to measure it."
            )
            return result

        result.verdict = VERDICT_NO_CHANGES
        offset = self.warp_schedule[-1] if self.warp_schedule else 0.0
        unobservable = [d.label for d in result.deltas if not d.observable]
        result.summary = (
            f"Device clock advanced {offset:g}h with an active banking persona "
            "(contacts, bank SMS, discharging battery). Zero anomalous API hooks "
            "and zero background exfiltration observed across the sampling window."
        )
        if unobservable:
            result.summary += (
                " Not every metric was readable on this device: "
                + ", ".join(unobservable)
                + " could not be measured and are reported as unavailable rather "
                "than as zero."
            )
        return result


# ── Helpers ────────────────────────────────────────────────────────────────


def compute_deltas(before: BehaviorSnapshot, after: BehaviorSnapshot) -> List[MetricDelta]:
    """Pair the snapshots metric by metric, keeping unreadable ones unreadable."""
    deltas: List[MetricDelta] = []
    for spec in METRICS:
        pre = before.metrics.get(spec.key)
        post = after.metrics.get(spec.key)
        observable = pre is not None and post is not None
        deltas.append(
            MetricDelta(
                key=spec.key,
                label=spec.label,
                before=pre,
                after=post,
                delta=(post - pre) if observable else None,
                observable=observable,
                threat_class=spec.threat_class,
                source=spec.source,
                meaning=spec.meaning,
            )
        )
    return deltas


def _detonation_summary(
    triggered: Sequence[MetricDelta], schedule: Sequence[float]
) -> str:
    offset = schedule[-1] if schedule else 0.0
    parts = ", ".join(f"{d.label} +{d.delta}" for d in triggered)
    return (
        f"Dormancy defeated: the sample initiated activity it was not performing "
        f"before the {offset:g}h time warp and banking-persona injection ({parts}). "
        "The counts are post-minus-pre over the sequence window, not a total for "
        "the run."
    )


def _is_sender_id(address: str) -> bool:
    """True for an alphanumeric DLT sender header, False for a phone number."""
    return any(ch.isalpha() for ch in address or "")


def _first_int(pattern: str, text: Optional[str]) -> Optional[int]:
    match = re.search(pattern, text or "", re.MULTILINE)
    return int(match.group(1)) if match else None


def _is_local_address(remote_hex: str) -> bool:
    """Loopback or unspecified peer, in /proc/net's hex encoding."""
    cleaned = (remote_hex or "").strip().upper()
    if not cleaned or set(cleaned) == {"0"}:
        return True
    if len(cleaned) == 8:
        # IPv4 is little-endian: 0100007F is 127.0.0.1, so the last octet leads.
        return cleaned.endswith("7F")
    # IPv6 loopback ::1, and the v4-mapped loopback both end in the v4 form.
    return cleaned.endswith("0000000000000001") or cleaned.endswith("7F000001")
