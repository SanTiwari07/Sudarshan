"""
A loader that renders nothing must not be reported as "never rendered a screen".

Some samples draw no UI of their own: they start, launch a SECOND package to
render the user-facing journey, and then idle. Measured on an e-challan sample
- `START cmp=<other>/.MainActivity from uid <sample>` 211ms after its own
MainActivity - where the four-field form the victim actually sees belongs
entirely to the other package.

Two layers got this wrong, independently, and both are covered here:

* **L2, instrumentation.** Frida attached to the target PID only, so every hook
  lived in the idle loader while the process doing the work was uninstrumented.
  Runtime evidence was empty for a reason that had nothing to do with the
  sample's behaviour.
* **L1, launch milestones.** `first_activity` / `first_window` were stamped only
  when the foreground window mentioned the TARGET package, so risk_engine's
  `_ui_never_rendered` reported NO_UI_RENDERED and excluded the dynamic axis -
  and the report said "the app never rendered a screen in the sandbox"
  underneath a screenshot of its form.

The detection is deliberately relationship-based: nothing here keys off a
package name, label or hash, because both the loader and its payload are
unknown packages.
"""

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.frida_sandbox import FridaSession  # noqa: E402
from sudarshan_core.engines.risk_engine import (  # noqa: E402
    _ui_never_rendered,
    dynamic_exclusion_reason,
)

TARGET = "com.loader.sample"
PAYLOAD = "com.payload.sample"


def _win(package: str) -> str:
    return (
        f"  mCurrentFocus=Window{{abc u0 {package}/{package}.MainActivity}}\n"
        f"  mFocusedApp=ActivityRecord{{def u0 {package}/.MainActivity t42}}"
    )


@pytest.fixture
def session(monkeypatch) -> FridaSession:
    """
    A session whose device answers are stubbed.

    Only the two device questions the detector asks are stubbed - "is this
    third party?" and "is the target alive?" - so the ordering and the
    frozenset exclusions are exercised for real.
    """
    s = FridaSession(device_serial="emulator-5554", package_name=TARGET)
    monkeypatch.setattr(
        FridaSession, "_is_third_party", lambda self, pkg: pkg == PAYLOAD,
    )
    monkeypatch.setattr(FridaSession, "_resolve_pid", lambda self: 4242)
    return s


# ─── Detection ───────────────────────────────────────────────────────────────

def test_a_package_the_sample_launched_is_detected_as_a_companion(session):
    assert session._detect_companion(_win(PAYLOAD)) == PAYLOAD


def test_the_target_in_its_own_foreground_is_not_a_companion(session):
    assert session._detect_companion(_win(TARGET)) is None


@pytest.mark.parametrize("package", [
    "com.google.android.apps.nexuslauncher",
    "com.android.settings",
    "com.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.android.systemui",
    "com.android.vpndialogs",
])
def test_a_system_surface_is_never_adopted_as_a_companion(session, package):
    """
    A launcher, a Settings page or a permission prompt is not a payload.

    These are the surfaces a sample legitimately sends the victim to, and
    §P24 already owns them as boundaries. Instrumenting them would put hooks
    in AOSP and attribute the platform's behaviour to the sample.
    """
    assert session._detect_companion(_win(package)) is None


def test_a_system_package_is_rejected_even_if_it_is_not_in_any_frozenset(
    session, monkeypatch,
):
    """
    The third-party test is what makes the exclusions general.

    A denylist of "packages that are not payloads" cannot be written - the
    payload's package name is unknown and frequently random - so the question
    is asked of the device instead: was this installed onto the image, or
    shipped with it?
    """
    monkeypatch.setattr(FridaSession, "_is_third_party", lambda self, pkg: False)
    assert session._detect_companion(_win("com.oem.unknownpreinstalled")) is None


def test_a_dead_target_did_not_hand_off_to_anything(session, monkeypatch):
    """
    A sample that died and left something else on screen did not hand off.

    Without this, any app the victim happened to be looking at after a crash
    would be instrumented and its behaviour attributed to the sample.
    """
    monkeypatch.setattr(FridaSession, "_resolve_pid", lambda self: 0)
    assert session._detect_companion(_win(PAYLOAD)) is None


def test_an_empty_reading_is_not_a_foreign_foreground(session):
    """
    "Not asked" and "asked, and the device said nothing" are different facts.

    Passing an empty string means the caller already read the window and got
    nothing; collapsing that into a fresh query would answer about a later
    moment than the one being judged.
    """
    assert session._detect_companion("") is None
    assert session._foreground_package("") == ""


def test_detection_is_idempotent_for_an_already_known_companion(session):
    session.companion_packages.append(PAYLOAD)
    assert session._detect_companion(_win(PAYLOAD)) == PAYLOAD
    assert session.companion_packages.count(PAYLOAD) == 1


# ─── L1: the launch milestones ───────────────────────────────────────────────

def test_a_companion_foreground_counts_as_the_app_having_rendered():
    """
    §L1: "did this app render a screen?" is a question about the app as the
    USER experiences it.

    A loader whose payload is drawing a form has rendered a screen. Recording
    otherwise made risk_engine exclude the dynamic axis as NO_UI_RENDERED for
    an app that was visibly on screen.
    """
    rendered = {
        "available": True,
        "launch_timeline": {"first_activity": 1.0, "first_window": 1.0},
    }
    assert _ui_never_rendered(rendered) is False
    assert dynamic_exclusion_reason(rendered) != "NO_UI_RENDERED"


def test_a_genuinely_headless_run_still_reports_no_ui_rendered():
    """
    The fix must not blind the check it repairs.

    A process that really never owned a window is still NO_UI_RENDERED, and
    that must keep excluding the axis - a UI-less run is not evidence of
    safety.
    """
    headless = {
        "available": True,
        "launch_timeline": {"first_activity": None, "first_window": None},
    }
    assert _ui_never_rendered(headless) is True
    assert dynamic_exclusion_reason(headless) == "NO_UI_RENDERED"


# ─── L2: what gets instrumented ──────────────────────────────────────────────

def test_a_companion_is_instrumented_with_the_same_agent(session, monkeypatch):
    """
    The payload gets the SAME hooks, so accessibility, SMS, overlay, network
    and banking are present in the process actually doing the work.
    """
    loaded = {}

    class _Script:
        def on(self, name, handler): loaded["handler"] = handler
        def load(self): loaded["loaded"] = True

    class _Session:
        def create_script(self, src):
            loaded["source"] = src
            return _Script()

    class _Device:
        def attach(self, pid):
            loaded["pid"] = pid
            return _Session()

    monkeypatch.setattr(
        "sudarshan_core.engines.frida_sandbox._adb",
        lambda *a, **k: (True, "9182"),
    )
    assert session._attach_companion(_Device(), PAYLOAD, "AGENT_SOURCE") is True
    assert loaded["pid"] == 9182
    assert loaded["source"] == "AGENT_SOURCE"
    assert loaded["loaded"] is True
    assert PAYLOAD in session.companion_packages


def test_a_companion_that_cannot_be_attached_does_not_kill_the_run(
    session, monkeypatch,
):
    """
    A run that cannot instrument the payload is a worse run, not a failed one.

    The target's own session must survive the attempt, and the report must
    still be produced - with the payload's silence recorded as absence of
    OBSERVATION rather than absence of behaviour.
    """
    class _Device:
        def attach(self, pid):
            raise RuntimeError("injection refused")

    monkeypatch.setattr(
        "sudarshan_core.engines.frida_sandbox._adb",
        lambda *a, **k: (True, "9182"),
    )
    assert session._attach_companion(_Device(), PAYLOAD, "AGENT") is False
    assert PAYLOAD not in session.companion_packages


def test_a_companion_with_no_process_is_not_attached(session, monkeypatch):
    monkeypatch.setattr(
        "sudarshan_core.engines.frida_sandbox._adb",
        lambda *a, **k: (True, ""),
    )

    class _Device:
        def attach(self, pid):        # pragma: no cover - must not be reached
            raise AssertionError("attach attempted without a PID")

    assert session._attach_companion(_Device(), PAYLOAD, "AGENT") is False


def test_companion_events_are_stamped_with_their_source_package(session):
    """
    Evidence from a payload is evidence about this investigation, but
    attributing it to the loader would be a fabrication.
    """
    seen = {}
    session._on_message = lambda message, data: seen.update(message)  # type: ignore[method-assign]
    handler = session._companion_message_handler(PAYLOAD)
    handler(
        {"type": "send", "payload": {"type": "event", "category": "sms",
                                     "data": {"hook": "SmsManager.send"}}},
        None,
    )
    assert seen["payload"]["source_package"] == PAYLOAD
    assert seen["payload"]["companion_of"] == TARGET


# ─── L0, the launch gate ─────────────────────────────────────────────────────
#
# A hand-off is a launch that SUCCEEDED. Judging it on "did the target own the
# window" reported a running, on-screen app as a failed launch, and the caller
# then walked its whole ladder of launch strategies - six attempts at ~12-19s
# each - re-launching an app that was already up. Measured on the e-challan
# sample: ~90s of a 300s window spent before exploration began.

def test_the_launch_gate_accepts_a_hand_off_as_a_rendered_launch(session, monkeypatch):
    from sudarshan_core.engines import frida_sandbox

    monkeypatch.setattr(
        frida_sandbox, "_adb", lambda *a, **k: (True, _win(PAYLOAD)),
    )
    rendered, owner = frida_sandbox._poll_until_package_owns_window(
        "emulator-5554", TARGET,
        total_timeout=1.0,
        accept_handoff=session._detect_companion,
    )
    assert rendered is True
    assert owner == PAYLOAD


def test_the_launch_gate_still_reports_a_target_that_never_renders(monkeypatch):
    """
    The gate must keep failing for the case it exists to catch: a process that
    is alive but never inflates an Activity.
    """
    from sudarshan_core.engines import frida_sandbox

    monkeypatch.setattr(
        frida_sandbox, "_adb",
        lambda *a, **k: (True, _win("com.google.android.apps.nexuslauncher")),
    )
    rendered, owner = frida_sandbox._poll_until_package_owns_window(
        "emulator-5554", TARGET, total_timeout=1.0, accept_handoff=lambda dump: None,
    )
    assert rendered is False
    assert owner == ""


def test_the_launch_gate_names_the_target_when_the_target_renders(monkeypatch):
    from sudarshan_core.engines import frida_sandbox

    monkeypatch.setattr(
        frida_sandbox, "_adb", lambda *a, **k: (True, _win(TARGET)),
    )
    rendered, owner = frida_sandbox._poll_until_package_owns_window(
        "emulator-5554", TARGET, total_timeout=1.0,
    )
    assert (rendered, owner) == (True, TARGET)


def test_a_failing_hand_off_probe_does_not_fail_the_launch_gate(monkeypatch):
    """A probe that raises must not decide the launch; the gate keeps waiting."""
    from sudarshan_core.engines import frida_sandbox

    def _boom(_dump):
        raise RuntimeError("adb went away")

    monkeypatch.setattr(
        frida_sandbox, "_adb", lambda *a, **k: (True, _win(PAYLOAD)),
    )
    rendered, owner = frida_sandbox._poll_until_package_owns_window(
        "emulator-5554", TARGET, total_timeout=0.6, accept_handoff=_boom,
    )
    assert (rendered, owner) == (False, "")


# ─── The timeline must survive its own metadata ──────────────────────────────

def test_a_package_name_in_the_timeline_does_not_destroy_the_run():
    """
    `launch_timeline` is typed as a map of monotonic floats, but it is a plain
    dict several code paths write to - and the hand-off path stored a package
    NAME in it. `_timeline_to_seconds` then raised
    `TypeError: unsupported operand type(s) for -: 'str' and 'float'` AFTER a
    complete dynamic run, which surfaced as a 500 from the analysis engine, a
    fail-closed 503 at the gateway, and a case reporting that dynamic analysis
    had never been performed.

    A malformed telemetry entry must cost that entry, never the telemetry.
    """
    from sudarshan_core.engines.frida_sandbox import _timeline_to_seconds

    out = _timeline_to_seconds({
        "apk_install": 100.0,
        "first_window": 103.5,
        "frida_attach": None,
        "first_window_package": "com.payload.sample",
    })
    assert out["first_window"] == 3.5
    assert out["frida_attach"] is None
    assert out["first_window_package"] == "com.payload.sample"


def test_the_timeline_is_still_offset_from_install_when_it_can_be():
    from sudarshan_core.engines.frida_sandbox import _timeline_to_seconds

    out = _timeline_to_seconds({"apk_install": 10.0, "first_pid": 12.25})
    assert out["first_pid"] == 2.25


def test_a_non_numeric_install_base_does_not_raise():
    from sudarshan_core.engines.frida_sandbox import _timeline_to_seconds

    out = _timeline_to_seconds({"apk_install": "n/a", "first_pid": 12.25})
    assert out["first_pid"] == 12.25
    assert out["apk_install"] == "n/a"


def test_the_hand_off_package_is_reported_off_the_timeline(session):
    """
    The package that drew the screen is real evidence and is still reported -
    it just travels as its own attribute instead of inside a map of floats.
    """
    assert session.first_window_package == ""
    session.first_window_package = PAYLOAD
    assert session.first_window_package == PAYLOAD


# ─── A crash of OURS is not a crash of the app's ─────────────────────────────
#
# Measured on the e-challan payload, API 37: an intermittent SIGSEGV on ART's
# "Jit thread pool" inside art::HBasicBlockBuilder::Build() / JitCompile - the
# JIT racing the hooks being installed into methods it is concurrently
# compiling. The same sample launches cleanly uninstrumented and survives the
# identical agent on a repeat attempt. Unhandled, it ended the whole dynamic
# run and the case reported no runtime evidence at all.
#
# The retry is deliberately narrow: an app that throws must still stop the
# ladder on the first attempt, or a genuinely broken sample spends the window
# being relaunched.

def _report(**kwargs):
    from sudarshan_core.engines.frida_sandbox import CrashReport

    return CrashReport(**kwargs)


def test_an_art_jit_segv_is_recognised_as_our_race():
    from sudarshan_core.engines.frida_sandbox import _crash_is_instrumentation_race

    assert _crash_is_instrumentation_race(_report(
        native_stacktrace=(
            "signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)\n"
            "  #00 pc 2bddbb /apex/com.android.art/lib64/libart.so "
            "(art::HBasicBlockBuilder::Build()+331)"
        ),
    )) is True


@pytest.mark.parametrize("marker", [
    "art::jit::JitCompiler::CompileMethod",
    "art::OptimizingCompiler::TryCompile",
    "art::HGraphBuilder::BuildGraph",
    "name: Jit thread pool",
])
def test_every_jit_frame_shape_is_recognised(marker):
    from sudarshan_core.engines.frida_sandbox import _crash_is_instrumentation_race

    assert _crash_is_instrumentation_race(_report(native_stacktrace=marker)) is True


def test_an_app_exception_is_never_retried():
    """
    A sample that throws is a sample that crashed. Retrying it would spend the
    analysis window relaunching an app that cannot run.
    """
    from sudarshan_core.engines.frida_sandbox import _crash_is_instrumentation_race

    assert _crash_is_instrumentation_race(_report(
        exception_type="java.lang.NullPointerException",
        java_stacktrace="at com.sample.Main.onCreate(Main.java:42)",
    )) is False


def test_a_java_exception_wins_even_beside_a_jit_frame():
    """
    Both present means the app threw. The Java side is the authoritative
    explanation and must not be overridden by an incidental native frame.
    """
    from sudarshan_core.engines.frida_sandbox import _crash_is_instrumentation_race

    assert _crash_is_instrumentation_race(_report(
        exception_type="java.lang.IllegalStateException",
        native_stacktrace="art::jit::JitCompiler::CompileMethod",
    )) is False


@pytest.mark.parametrize("report_kwargs", [
    {},
    {"native_stacktrace": ""},
    {"native_stacktrace": "#00 libc.so (abort+164)"},
])
def test_an_unrelated_or_absent_crash_is_not_retried(report_kwargs):
    from sudarshan_core.engines.frida_sandbox import _crash_is_instrumentation_race

    assert _crash_is_instrumentation_race(_report(**report_kwargs)) is False


def test_no_report_at_all_is_not_retried():
    from sudarshan_core.engines.frida_sandbox import _crash_is_instrumentation_race

    assert _crash_is_instrumentation_race(None) is False


def test_the_retry_budget_is_bounded_and_configurable():
    from sudarshan_core.engines import frida_sandbox

    assert 1 <= frida_sandbox.MAX_INSTRUMENTATION_RACE_RETRIES <= 5
    assert frida_sandbox.INSTRUMENTATION_RACE_BACKOFF_SECONDS > 0
