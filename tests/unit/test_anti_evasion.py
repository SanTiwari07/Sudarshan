"""Autonomous anti-evasion: the sequence, and the honesty of its verdict.

The device is faked, so what is under test is everything that has to be right
before a real one is involved:

  * the sequence applies three cumulative clock offsets and pairs each with the
    framework lever that actually releases deferred work,
  * a metric the device would not surface stays *unavailable* end to end and
    never collapses into a zero,
  * ``NO_CHANGES_OBSERVED`` - the clean bill of health - is unreachable unless
    the hook stream was attached, and
  * a delta any app produces cannot promote the verdict to detonated.

The last two are the whole point of the module. A false "benign" on an
unobserved run and a false "malware" on an ordinary socket are the two ways
this feature could lie to an analyst.
"""

import calendar
import datetime
import re
from typing import Dict, List, Optional, Tuple

import pytest

from sudarshan_core.engines.anti_evasion import (
    VERDICT_DETONATED,
    VERDICT_NO_CHANGES,
    VERDICT_NO_TELEMETRY,
    AntiEvasionOrchestrator,
    BehaviorSnapshot,
    compute_deltas,
)

PACKAGE = "com.evil.dropper"

WINDOW_DUMP = """
  Window #0 Window{aaaa u0 StatusBar}:
    mOwnerUid=1000
    ty=STATUS_BAR
  Window #1 Window{bbbb u0 com.evil.dropper/com.evil.dropper.MainActivity}:
    mOwnerUid=10188
    ty=BASE_APPLICATION
  Window #2 Window{cccc u0 com.evil.dropper}:
    mOwnerUid=10188
    ty=APPLICATION_OVERLAY
"""

PROC_NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1
   1: 0F00020A:C350 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000 10188        0 12346 1
   2: 0F00020A:C351 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 10188        0 12347 1
   3: 0F00020A:C352 08080808:01BB 01 00000000:00000000 00:00000000 00000000 10001        0 12348 1
"""


class FakeDevice:
    """A device that answers the dumps this module reads, and records commands."""

    def __init__(
        self,
        *,
        api: int = 33,
        overlay_windows: str = WINDOW_DUMP,
        accessibility_bound: bool = False,
        battery_level: int = 100,
        battery_accepts_override: bool = True,
        proc_net: str = PROC_NET_TCP,
        seeded_contacts: int = 0,
        readable: Tuple[str, ...] = (),
    ):
        self.api = api
        self.epoch = 1_760_000_000
        self.overlay_windows = overlay_windows
        self.accessibility_bound = accessibility_bound
        self.battery_level = battery_level
        self.battery_status = 2
        self.battery_accepts_override = battery_accepts_override
        self.proc_net = proc_net
        self.rows = {"raw_contacts": seeded_contacts, "calls": 0, "sms": 0, "photos": 0}
        self.seeded_sms_addresses: set = set()
        #: Dumps that are unreadable on this device, by substring.
        self.unreadable: Tuple[str, ...] = readable
        self.commands: List[str] = []

    def adb_shell(self, serial: str, command: str, timeout: int = 30) -> Tuple[bool, str]:
        self.commands.append(command)
        for marker in self.unreadable:
            if marker in command:
                return False, "Permission denial"

        if command.startswith("getprop ro.build.version.sdk"):
            return True, str(self.api)
        if command == "date +%s":
            return True, str(self.epoch)
        if command.startswith("date "):
            self._apply_date(command.split(" ", 1)[1])
            return True, ""
        if command.startswith("settings put global auto_time"):
            return True, ""
        if command.startswith("settings get secure enabled_accessibility_services"):
            return True, f"{PACKAGE}/.Svc" if self.accessibility_bound else "null"
        if command == "dumpsys jobscheduler":
            return True, "JOB SCHEDULER STATE\nRegistered 0 jobs:\n"
        if command.startswith("dumpsys deviceidle"):
            return True, ""
        if command.startswith("dumpsys battery set level"):
            if self.battery_accepts_override:
                self.battery_level = int(command.rsplit(" ", 1)[1])
            return True, ""
        if command.startswith("dumpsys battery set status"):
            if self.battery_accepts_override:
                self.battery_status = int(command.rsplit(" ", 1)[1])
            return True, ""
        if command in ("dumpsys battery unplug", "dumpsys battery reset"):
            return True, ""
        if command == "dumpsys battery":
            return True, (
                f"Current Battery Service state:\n  AC powered: false\n"
                f"  status: {self.battery_status}\n  level: {self.battery_level}\n"
            )
        if command == "dumpsys window windows":
            return True, self.overlay_windows
        if command == "dumpsys accessibility":
            services = f"{{ComponentInfo{{{PACKAGE}/.Svc}}}}" if self.accessibility_bound else "{}"
            return True, f"User state[attributes:0]\n     Bound services:{services}\n"
        if command.startswith("cmd package list packages -U"):
            return True, f"package:{PACKAGE} uid:10188"
        if command.startswith("cat /proc/net/tcp"):
            return True, self.proc_net
        if command.startswith("ls /sdcard/DCIM"):
            return True, str(self.rows["photos"])
        if "content query" in command:
            # Per provider, and only rows that were actually inserted: the
            # already-seeded checks and the raw-contact id read-back all query
            # different URIs and must not see each other's rows.
            provider = self._provider_of(command)
            count = self.rows.get(provider, 0)
            if provider == "sms":
                return True, "\n".join(
                    f"Row: {i} address={a}"
                    for i, a in enumerate(sorted(self.seeded_sms_addresses))
                )
            return True, "\n".join(f"Row: {i} _id={i + 1}" for i in range(count))
        if "content insert" in command:
            provider = self._provider_of(command)
            inserts = command.count("content insert")
            if provider == "sms":
                for token in command.split():
                    if token.startswith("address:s:"):
                        self.seeded_sms_addresses.add(token.split("address:s:", 1)[1].strip("'"))
            if provider in ("raw_contacts", "calls", "sms"):
                self.rows[provider] = self.rows.get(provider, 0) + inserts
            return True, "__OK__\n" * command.count("__OK__")
        if "base64 -d" in command:
            self.rows["photos"] += 1
            return True, ""
        return True, ""

    @staticmethod
    def _provider_of(command: str) -> str:
        if "raw_contacts" in command:
            return "raw_contacts"
        if "call_log" in command:
            return "calls"
        if "sms" in command:
            return "sms"
        if "com.android.contacts/data" in command:
            return "contact_data"
        return "other"

    def check_root(self, serial: str) -> bool:
        return True

    def _apply_date(self, arg: str) -> None:
        if arg.startswith("@"):
            self.epoch = int(arg[1:])
            return
        match = re.match(r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{4})\.(\d{2})$", arg)
        if match:
            mo, d, h, mi, y, s = (int(x) for x in match.groups())
            self.epoch = calendar.timegm(datetime.datetime(y, mo, d, h, mi, s).timetuple())


def probe(attached: bool, **counts: int):
    """A telemetry probe returning fixed hook-category counts."""

    def _probe() -> Dict[str, object]:
        return {
            "attached": attached,
            "source": "in-process Frida hook telemetry",
            "counts": dict(counts),
        }

    return _probe


def orchestrator(device: FakeDevice, probe_fn=None, **kwargs) -> AntiEvasionOrchestrator:
    return AntiEvasionOrchestrator(
        "emulator-5554",
        PACKAGE,
        telemetry_probe=probe_fn,
        provider=device,
        **kwargs,
    )


def snapshot_with(**metrics: Optional[int]) -> BehaviorSnapshot:
    base = {
        "sms_reads": None,
        "c2_requests": None,
        "accessibility_events": None,
        "overlay_events": None,
        "overlay_windows": None,
        "accessibility_service_bound": None,
        "network_connections": None,
    }
    base.update(metrics)
    return BehaviorSnapshot(
        captured_at=1.0,
        hooks_attached=any(
            base[k] is not None
            for k in ("sms_reads", "c2_requests", "accessibility_events", "overlay_events")
        ),
        metrics=base,
    )


# ── Device probes ──────────────────────────────────────────────────────────


def test_overlay_windows_counted_only_for_the_package():
    """A status bar is not the sample's overlay, and a base activity is not one either."""
    orch = orchestrator(FakeDevice())
    assert orch.overlay_window_count() == 1


def test_unreadable_window_dump_is_unavailable_not_zero():
    orch = orchestrator(FakeDevice(readable=("dumpsys window",)))
    assert orch.overlay_window_count() is None


def test_accessibility_binding_read_from_dump_and_setting():
    assert orchestrator(FakeDevice(accessibility_bound=True)).accessibility_service_bound() == 1
    assert orchestrator(FakeDevice(accessibility_bound=False)).accessibility_service_bound() == 0


def test_accessibility_falls_back_to_the_setting_when_the_dump_fails():
    device = FakeDevice(accessibility_bound=True, readable=("dumpsys accessibility",))
    assert orchestrator(device).accessibility_service_bound() == 1


def test_connections_filtered_by_uid_and_exclude_loopback():
    """One established remote connection: the loopback and the other uid do not count."""
    orch = orchestrator(FakeDevice())
    assert orch.established_connection_count() == 1


def test_connections_unavailable_when_proc_net_is_restricted():
    orch = orchestrator(FakeDevice(readable=("/proc/net/tcp",)))
    assert orch.established_connection_count() is None


# ── Snapshots ──────────────────────────────────────────────────────────────


def test_snapshot_reports_hook_metrics_as_unknown_without_a_stream():
    """No attached hooks means no API-level observation - not zero of it."""
    snap = orchestrator(FakeDevice(), probe(False, sms=17)).snapshot()
    assert snap.hooks_attached is False
    assert snap.metrics["sms_reads"] is None
    assert snap.metrics["c2_requests"] is None
    # Device-side observation still works without Frida.
    assert snap.metrics["overlay_windows"] == 1
    assert any("no frida hook stream" in n.lower() for n in snap.notes)


def test_snapshot_maps_hook_categories_onto_metrics():
    snap = orchestrator(
        FakeDevice(), probe(True, sms=4, network=9, accessibility=2, overlay=1)
    ).snapshot()
    assert snap.hooks_attached is True
    assert snap.metrics["sms_reads"] == 4
    assert snap.metrics["c2_requests"] == 9
    assert snap.metrics["accessibility_events"] == 2
    assert snap.metrics["overlay_events"] == 1


def test_missing_category_with_a_live_stream_is_zero_not_unknown():
    """The stream was attached and reported nothing in that category: a real zero."""
    snap = orchestrator(FakeDevice(), probe(True, network=3)).snapshot()
    assert snap.metrics["sms_reads"] == 0


def test_a_failing_probe_is_recorded_not_swallowed():
    def explode():
        raise RuntimeError("telemetry buffer gone")

    snap = orchestrator(FakeDevice(), explode).snapshot()
    assert snap.metrics["sms_reads"] is None
    assert any("telemetry buffer gone" in n for n in snap.notes)


# ── Deltas ─────────────────────────────────────────────────────────────────


def test_delta_of_an_unobservable_metric_stays_none():
    deltas = {
        d.key: d
        for d in compute_deltas(snapshot_with(sms_reads=None), snapshot_with(sms_reads=None))
    }
    assert deltas["sms_reads"].delta is None
    assert deltas["sms_reads"].observable is False


def test_delta_is_post_minus_pre():
    deltas = {
        d.key: d
        for d in compute_deltas(snapshot_with(sms_reads=2), snapshot_with(sms_reads=11))
    }
    assert deltas["sms_reads"].delta == 9
    assert deltas["sms_reads"].observable is True


# ── Verdicts ───────────────────────────────────────────────────────────────


def test_threat_delta_detonates():
    orch = orchestrator(FakeDevice())
    before = snapshot_with(sms_reads=0, c2_requests=0, accessibility_events=0, overlay_events=0)
    after = snapshot_with(sms_reads=6, c2_requests=3, accessibility_events=0, overlay_events=0)
    result = orch.summarise(before, after, [])
    assert result.verdict == VERDICT_DETONATED
    assert set(result.triggered_keys) == {"sms_reads", "c2_requests"}
    assert "6" in result.summary and "3" in result.summary


def test_device_observed_overlay_alone_detonates():
    """An overlay window that appeared during the sequence is threat-class on its own."""
    orch = orchestrator(FakeDevice())
    before = snapshot_with(sms_reads=0, c2_requests=0, overlay_windows=0)
    after = snapshot_with(sms_reads=0, c2_requests=0, overlay_windows=1)
    assert orch.summarise(before, after, []).verdict == VERDICT_DETONATED


def test_socket_growth_alone_never_detonates():
    """Every app opens sockets. A connection count is context, not a verdict."""
    orch = orchestrator(FakeDevice())
    before = snapshot_with(sms_reads=0, c2_requests=0, network_connections=0)
    after = snapshot_with(sms_reads=0, c2_requests=0, network_connections=4)
    result = orch.summarise(before, after, [])
    assert result.verdict == VERDICT_NO_CHANGES
    assert result.triggered_keys == []


def test_benign_sample_reports_measured_zeroes():
    orch = orchestrator(FakeDevice())
    quiet = dict(sms_reads=0, c2_requests=0, accessibility_events=0, overlay_events=0)
    result = orch.summarise(snapshot_with(**quiet), snapshot_with(**quiet), [])
    assert result.verdict == VERDICT_NO_CHANGES
    assert all((d.delta == 0) for d in result.deltas if d.observable)
    assert "24h" in result.summary


def test_unobserved_run_is_never_a_clean_bill_of_health():
    """
    The zero-false-positive rule has a twin: no false negatives from silence.

    Nothing was watching the process, so nothing was observed. Reporting that
    as "no suspicious behaviour" would be the same error the execution
    assertion matrix exists to prevent.
    """
    orch = orchestrator(FakeDevice())
    before = snapshot_with(overlay_windows=0, network_connections=0)
    after = snapshot_with(overlay_windows=0, network_connections=0)
    result = orch.summarise(before, after, [])
    assert result.verdict == VERDICT_NO_TELEMETRY
    assert "no frida hook stream" in result.summary.lower()


def test_unreadable_metrics_are_named_in_a_clean_verdict():
    orch = orchestrator(FakeDevice())
    quiet = dict(sms_reads=0, c2_requests=0, accessibility_events=0, overlay_events=0)
    result = orch.summarise(snapshot_with(**quiet), snapshot_with(**quiet), [])
    assert "unavailable rather than as zero" in result.summary


# ── Sequence ───────────────────────────────────────────────────────────────


def test_schedule_advances_cumulatively_and_pairs_doze_levers():
    device = FakeDevice()
    orch = orchestrator(device)
    steps = orch.steps()
    assert [s.key for s in steps][:3] == ["warp_6h", "warp_12h", "warp_24h"]
    assert [s.key for s in steps][3:] == ["battery", "contacts", "calls", "sms", "photos"]

    start = device.epoch
    results = [s.run() for s in steps]

    # +6h, then +6h more, then +12h more: the device ends 24h ahead.
    assert (device.epoch - start) / 3600 == pytest.approx(24, abs=0.1)
    assert results[0].data["time_warp"]["requested_hours"] == 6.0
    assert results[2].data["time_warp"]["requested_hours"] == 12.0

    # The scheduler sweep is paid for once; Doze is entered, then released.
    assert device.commands.count("dumpsys jobscheduler") == 1
    assert results[1].data["doze_forced"] is True
    assert results[2].data["doze_released"] is True
    assert "dumpsys deviceidle force-idle" in device.commands
    assert "dumpsys deviceidle unforce" in device.commands


def test_battery_step_verifies_the_read_back():
    device = FakeDevice()
    step = orchestrator(device)._seed_battery()
    assert step.ok is True
    assert step.data["observed_level"] == 50
    assert step.data["observed_status"] == 3
    # The override outlives the sequence, and the analyst is told so.
    assert any("dumpsys battery reset" in w for w in step.warnings)


def test_battery_step_reports_a_refused_override():
    device = FakeDevice(battery_accepts_override=False)
    step = orchestrator(device)._seed_battery()
    assert step.ok is False
    assert step.data["observed_level"] == 100
    assert step.errors


def test_battery_step_does_not_claim_success_when_unreadable():
    device = FakeDevice(readable=("dumpsys battery",))
    step = orchestrator(device)._seed_battery()
    assert step.ok is False
    assert step.data["observed_level"] is None
    assert "unverified" in " ".join(step.errors)


def test_battery_runs_after_the_warps_because_doze_cycling_resets_it():
    """`cycle_doze` ends with `dumpsys battery reset`; seeding first would be undone."""
    keys = [s.key for s in orchestrator(FakeDevice()).steps()]
    assert keys.index("battery") > keys.index("warp_24h")


# ── Persona slice ──────────────────────────────────────────────────────────


def test_persona_is_trimmed_to_the_seeded_rows():
    """
    A slice of the template, not all of it.

    The full persona is 120 contacts, and `content insert` costs a process
    spawn per row - a complete seed takes minutes and times the request out.
    Twelve contacts clear an emptiness check just as well.
    """
    orch = orchestrator(
        FakeDevice(), contact_count=12, sms_count=4, call_count=10, photo_count=3
    )
    persona = orch._trimmed_persona()
    assert len(persona.contacts) == 12
    assert len(persona.messages) == 4
    assert len(persona.calls) == 10
    assert len(persona.photos) == 3


def test_transactional_senders_are_seeded_before_personal_numbers():
    """An evasive sample reads the inbox for bank headers, not for chat."""
    orch = orchestrator(FakeDevice(), sms_count=4)
    persona = orch._trimmed_persona()
    assert all(any(ch.isalpha() for ch in m.address) for m in persona.messages)


def test_seed_steps_report_rows_the_device_accepted():
    device = FakeDevice()
    orch = orchestrator(device, contact_count=12, sms_count=4)
    contacts = orch._seed_contacts()
    assert contacts.ok is True
    assert contacts.data["inserted"] == 12

    sms = orch._seed_sms()
    assert sms.data["inserted"] == 4


def test_a_refused_provider_is_an_error_not_a_silent_pass():
    device = FakeDevice()
    device.unreadable = ("content insert",)
    step = orchestrator(device)._seed_sms()
    assert step.ok is False
    assert step.data["inserted"] == 0
    assert "still unmet" in " ".join(step.errors)


# ── Result assembly ────────────────────────────────────────────────────────


def test_result_carries_step_warnings_and_the_run_flag():
    device = FakeDevice()
    orch = orchestrator(device, probe(True, sms=0))
    before = orch.snapshot()
    steps = [s.run() for s in orch.steps()]
    after = orch.snapshot()
    result = orch.summarise(before, after, steps, session_id="abc123")

    payload = result.to_dict()
    assert payload["session_id"] == "abc123"
    assert payload["ok"] is True
    assert payload["verdict"] == VERDICT_NO_CHANGES
    assert len(payload["steps"]) == len(steps)
    assert {d["key"] for d in payload["deltas"]} >= {"sms_reads", "network_connections"}
    assert payload["before"]["metrics"]["sms_reads"] == 0


# ── Whole sequence, as the sandbox runs it ─────────────────────────────────


def test_run_sequence_measures_and_then_puts_the_device_back():
    """
    The mid-session path. The clock must not be left 24h ahead: the sequence
    runs on every dynamic analysis, and a sandbox that is never re-imaged would
    drift a day per sample until TLS stops working.
    """
    device = FakeDevice()
    start_epoch = device.epoch
    orch = orchestrator(device, probe(True, sms=0, network=0))

    result = orch.run_sequence(observation_seconds=0, session_id="s1")

    keys = [s.key for s in result.steps]
    assert keys[-2:] == ["observe", "restore"]
    assert result.verdict == VERDICT_NO_CHANGES
    # Clock back where it started, and automatic sync re-enabled.
    assert abs(device.epoch - start_epoch) < 120
    assert device.commands.count("settings put global auto_time 1") == 1
    assert "dumpsys battery reset" in device.commands


def test_run_sequence_can_leave_the_device_warped():
    device = FakeDevice()
    start_epoch = device.epoch
    orchestrator(device, probe(True)).run_sequence(observation_seconds=0, restore=False)
    assert (device.epoch - start_epoch) / 3600 == pytest.approx(24, abs=0.1)


def test_restore_does_not_rewind_a_clock_that_never_moved():
    """Rewinding an unwarped device would introduce the drift restore prevents."""
    device = FakeDevice()
    start_epoch = device.epoch
    step = orchestrator(device)._seed_battery()
    assert step.ok
    orchestrator(device).restore()
    assert device.epoch == start_epoch


def test_one_failing_step_does_not_abandon_the_rest():
    device = FakeDevice()
    device.unreadable = ("content insert",)
    result = orchestrator(device, probe(True)).run_sequence(observation_seconds=0)
    keys = {s.key for s in result.steps}
    assert {"warp_24h", "battery", "sms", "restore"} <= keys
    assert any(s.key == "sms" and not s.ok for s in result.steps)
    assert result.ok is True  # the warp and the battery still landed


def test_an_already_furnished_device_is_not_seeded_again():
    """Re-seeding every run would grow the address book without bound."""
    device = FakeDevice(seeded_contacts=12)
    step = orchestrator(device, contact_count=12)._seed_contacts()
    assert step.ok is True
    assert step.data == {"inserted": 0, "already_present": 12}
    assert not any("content insert" in c for c in device.commands)


# ── What the device actually ended up with ─────────────────────────────────


def test_applied_changes_report_the_clock_ends_and_the_rows_written():
    """
    The analyst has to be able to see the sequence worked.

    A verdict of "nothing observed" is a statement about the sample; without
    the applied changes beside it there is no way to tell that from a control
    that silently did nothing.
    """
    device = FakeDevice()
    orch = orchestrator(device, probe(True), contact_count=12, sms_count=4)
    result = orch.run_sequence(observation_seconds=0, restore=False)
    applied = result.applied_changes

    assert applied.clock_before_ms == 1_760_000_000 * 1000
    assert (applied.clock_after_ms - applied.clock_before_ms) / 3_600_000 == pytest.approx(
        24, abs=0.1
    )
    assert applied.clock_shift_hours == pytest.approx(24, abs=0.1)
    assert applied.doze_cycled is True
    assert applied.battery_level == 50
    assert applied.seeded["contacts"] == 12
    assert applied.seeded["sms"] == 4
    assert applied.seeded["calls"] == 10


def test_applied_changes_distinguish_skipped_from_refused():
    """Rows already on the device are reported as present, not as written."""
    device = FakeDevice(seeded_contacts=12)
    result = orchestrator(device, probe(True), contact_count=12).run_sequence(
        observation_seconds=0, restore=False
    )
    applied = result.applied_changes
    assert applied.already_present["contacts"] == 12
    assert "contacts" not in applied.seeded


def test_applied_changes_survive_the_json_round_trip():
    device = FakeDevice()
    payload = orchestrator(device, probe(True)).run_sequence(
        observation_seconds=0, restore=False
    ).to_dict()
    applied = payload["applied_changes"]
    assert applied["clock_shift_hours"] == pytest.approx(24, abs=0.1)
    assert applied["seeded"]["contacts"] == 12
    assert applied["battery_level"] == 50
