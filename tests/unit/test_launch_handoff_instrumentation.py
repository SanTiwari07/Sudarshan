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
