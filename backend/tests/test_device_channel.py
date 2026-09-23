"""
Regression tests for the persistent device channel.

The defect: every device interaction went through `subprocess.run([adb, ...])`.
One perception cycle cost six process spawns (uiautomator dump, cat, dumpsys,
screencap, pull, rm) and one explorer action ten to fifteen once verification
re-dumped - each spawn also opening a TCP connection to an ADB server that,
under Docker, lives on the host. Measured: 5 actions in 611 seconds against a
300-second budget, coverage_percent 0, 1 of 2 forms completed.

The contract now:
  * the channel is used when available and the ADB path remains as fallback,
    so a sandbox without the on-device agent is slow, never broken
  * ADB_SERVER_SOCKET is translated for libraries that speak ADB directly
  * text goes into a field by NODE, not by whatever holds focus

No device needed.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest


DC = "sudarshan_core.sandbox.device_channel"


@pytest.fixture(autouse=True)
def _clear_channel_registry():
    from sudarshan_core.sandbox import device_channel

    device_channel.close_all()
    yield
    device_channel.close_all()


# ── ADB server env translation ────────────────────────────────────────────────


def test_adb_server_socket_is_translated_for_direct_adb_clients(monkeypatch):
    """
    adbutils and uiautomator2 read ADB_SERVER_HOST/PORT and know nothing about
    ADB_SERVER_SOCKET, which is an `adb` BINARY flag. Without the translation a
    container configured correctly for the CLI has uiautomator2 dialling its
    own empty loopback.
    """
    from sudarshan_core.sandbox.device_channel import _export_adb_server_env

    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:host.docker.internal:5037")
    monkeypatch.setenv("RUNNING_IN_DOCKER", "true")
    monkeypatch.delenv("ADB_SERVER_HOST", raising=False)
    monkeypatch.delenv("ADB_SERVER_PORT", raising=False)

    _export_adb_server_env()

    import os
    assert os.environ["ADB_SERVER_HOST"] == "host.docker.internal"
    assert os.environ["ADB_SERVER_PORT"] == "5037"


def test_adb_server_port_parses_non_default_port(monkeypatch):
    from sudarshan_core.sandbox.config import adb_server_port

    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:10.0.0.4:5555")
    assert adb_server_port() == 5555
    monkeypatch.delenv("ADB_SERVER_SOCKET")
    assert adb_server_port() == 5037


# ── degradation ───────────────────────────────────────────────────────────────


def test_channel_reports_unavailable_when_uiautomator2_is_missing(monkeypatch):
    """A missing wheel must slow the run down, never end it."""
    from sudarshan_core.sandbox.device_channel import get_channel

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def _no_u2(name, *args, **kwargs):
        if name == "uiautomator2":
            raise ImportError("no module named uiautomator2")
        return real_import(name, *args, **kwargs)

    channel = get_channel("emulator-5554")
    with patch("builtins.__import__", side_effect=_no_u2):
        assert channel.available is False
        assert channel.dump_hierarchy() is None
        assert channel.screenshot("/tmp/x.png") is False
        assert channel.click_xy(1, 2) is False
        assert channel.set_text_focused("value") is False
        assert channel.shell("echo hi") is None


def test_failed_connect_is_not_retried_on_every_call(monkeypatch):
    """
    A device that cannot be reached must be asked once. Retrying per call would
    add a failed connection attempt to every single interaction - strictly worse
    than the subprocess path it replaces.
    """
    from sudarshan_core.sandbox.device_channel import get_channel

    fake_u2 = MagicMock()
    fake_u2.connect.side_effect = RuntimeError("device offline")
    channel = get_channel("emulator-5554")

    with patch.dict("sys.modules",
                    {"uiautomator2": fake_u2, "adbutils": MagicMock()}):
        assert channel.available is False
        assert channel.available is False
        assert channel.dump_hierarchy() is None

    assert fake_u2.connect.call_count == 1


def test_shell_distinguishes_no_channel_from_command_failure():
    """
    None means "no channel, use adb"; (False, out) means "ran and failed".
    Collapsing the two would make callers fall back after a real failure and
    run the same command twice.
    """
    from sudarshan_core.sandbox.device_channel import get_channel

    channel = get_channel("emulator-5554")
    assert channel.shell("echo hi") is None          # not connected

    device = MagicMock()
    result = MagicMock()
    result.output = "boom"
    result.exit_code = 1
    device.shell.return_value = result
    channel._d = device

    assert channel.shell("false") == (False, "boom")


# ── node-targeted input ───────────────────────────────────────────────────────


def test_set_text_node_writes_to_the_named_field():
    from sudarshan_core.sandbox.device_channel import get_channel

    channel = get_channel("emulator-5554")
    node = MagicMock()
    node.exists = True
    device = MagicMock(return_value=node)
    channel._d = device

    assert channel.set_text_node("hunter2", resourceId="com.x:id/pass") is True
    device.assert_called_once_with(resourceId="com.x:id/pass")
    node.set_text.assert_called_once_with("hunter2")


def test_set_text_node_fails_rather_than_typing_somewhere_else():
    """
    The launcher-typing bug. `input text` writes wherever focus happens to be;
    a real run recorded generated credentials typed into
    com.google.android.apps.nexuslauncher. An unresolvable node must be a
    reported failure, never a blind write.
    """
    from sudarshan_core.sandbox.device_channel import get_channel

    channel = get_channel("emulator-5554")
    node = MagicMock()
    node.exists = False
    channel._d = MagicMock(return_value=node)

    assert channel.set_text_node("hunter2", resourceId="com.x:id/pass") is False
    node.set_text.assert_not_called()


def test_current_activity_matches_the_dumpsys_component_shape():
    """
    Callers parse `package/activity` from dumpsys. The channel must answer in
    the same shape or activity comparisons silently stop matching.
    """
    from sudarshan_core.sandbox.device_channel import get_channel

    channel = get_channel("emulator-5554")
    device = MagicMock()
    device.app_current.return_value = {
        "package": "com.test.bank", "activity": ".MainActivity",
    }
    channel._d = device

    assert channel.current_activity() == "com.test.bank/.MainActivity"


# ── callers fall back ─────────────────────────────────────────────────────────


def test_perception_dump_falls_back_to_adb_when_channel_is_unavailable():
    from sudarshan_core.engines.agentic.perception import PerceptionPipeline

    pipeline = PerceptionPipeline.__new__(PerceptionPipeline)
    pipeline.device_serial = "emulator-5554"

    calls = []

    async def _fake_adb(*args):
        calls.append(args)
        if args[:2] == ("shell", "cat"):
            return True, '<?xml version="1.0"?><hierarchy/>'
        return True, ""

    pipeline._adb = _fake_adb
    channel = MagicMock()
    channel.dump_hierarchy.return_value = None      # unavailable

    with patch(f"{DC}.get_channel", return_value=channel):
        xml = asyncio.run(pipeline._dump_ui_xml())

    assert xml is not None and "hierarchy" in xml
    assert ("shell", "uiautomator", "dump", "/data/local/tmp/ui_dump.xml") in calls


def test_perception_dump_prefers_the_channel_and_skips_adb_entirely():
    from sudarshan_core.engines.agentic.perception import PerceptionPipeline

    pipeline = PerceptionPipeline.__new__(PerceptionPipeline)
    pipeline.device_serial = "emulator-5554"

    calls = []

    async def _fake_adb(*args):
        calls.append(args)
        return True, ""

    pipeline._adb = _fake_adb
    channel = MagicMock()
    channel.dump_hierarchy.return_value = '<?xml version="1.0"?><hierarchy/>'

    with patch(f"{DC}.get_channel", return_value=channel):
        xml = asyncio.run(pipeline._dump_ui_xml())

    assert "hierarchy" in xml
    assert calls == [], "the channel answered; no subprocess should have run"


# ── the IME must not be mistaken for the app ─────────────────────────────────


def _pipeline():
    from sudarshan_core.engines.agentic.perception import PerceptionPipeline

    p = PerceptionPipeline.__new__(PerceptionPipeline)
    p.device_serial = "emulator-5554"
    p.package_name = "com.hsjjsjs.android"
    return p


_IME_ONLY = (
    '<?xml version="1.0"?><hierarchy><node class="android.widget.EditText" '
    'package="com.google.android.inputmethod.latin" '
    'resource-id="com.google.android.inputmethod.latin:id/0_resource_name_obfuscated" '
    'text="Write here"/></hierarchy>'
)
_APP_FORM = (
    '<?xml version="1.0"?><hierarchy>'
    '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
    'resource-id="fullName" text="" hint="Full Name*"/>'
    '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
    'resource-id="mb" text="" hint="Mobile Number*"/>'
    '</hierarchy>'
)
_BOTH = _APP_FORM.replace(
    "</hierarchy>",
    '<node class="android.widget.FrameLayout" '
    'package="com.google.android.inputmethod.latin"/></hierarchy>',
)


def test_keyboard_only_hierarchy_is_detected():
    """
    Measured live against the eChallan payload: after a field was filled, the
    whole dump collapsed to Gboard's own node and the app's four EditTexts were
    absent. Everything downstream then reads as "the app has no fields".
    """
    assert _pipeline()._hierarchy_is_the_keyboards(_IME_ONLY) is True


def test_a_dump_containing_the_app_is_not_the_keyboards():
    """The IME sharing the screen with the app is normal and must not trigger."""
    p = _pipeline()
    assert p._hierarchy_is_the_keyboards(_APP_FORM) is False
    assert p._hierarchy_is_the_keyboards(_BOTH) is False


def test_a_payload_owned_screen_is_not_mistaken_for_the_keyboard():
    """
    The dropper case, and why this cannot key on the TARGET package. Anubis
    (com.tjmonh.android) hands the foreground to com.hsjjsjs.android, and the
    credential form belongs to the payload - so the target is legitimately
    absent from a perfectly good dump. Treating that as "the keyboard owns the
    screen" would press BACK and navigate away from the very form the run
    exists to observe.
    """
    p = _pipeline()
    p.package_name = "com.tjmonh.android"        # target, NOT the payload
    payload_with_ime = (
        '<?xml version="1.0"?><hierarchy>'
        '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
        'resource-id="fullName" hint="Full Name*"/>'
        '<node class="android.widget.FrameLayout" '
        'package="com.google.android.inputmethod.latin"/>'
        '</hierarchy>'
    )
    assert p._hierarchy_is_the_keyboards(payload_with_ime) is False


def test_system_bars_alone_do_not_count_as_app_content():
    """
    The status and navigation bars appear in nearly every dump. If they counted
    as app content the guard would never fire.
    """
    p = _pipeline()
    ime_plus_bars = (
        '<?xml version="1.0"?><hierarchy>'
        '<node package="com.android.systemui" resource-id="statusbar"/>'
        '<node class="android.widget.EditText" '
        'package="com.google.android.inputmethod.latin" text="Write here"/>'
        '</hierarchy>'
    )
    assert p._hierarchy_is_the_keyboards(ime_plus_bars) is True


def test_dump_dismisses_the_keyboard_and_returns_the_app_hierarchy():
    """
    Confirmed on the device: BACK dismissed the IME and the form reappeared
    with the previously typed value still in place.
    """
    p = _pipeline()
    channel = MagicMock()
    channel.dump_hierarchy.side_effect = [_IME_ONLY, _APP_FORM]
    channel.press.return_value = True

    async def _adb(*args):
        return True, ""

    p._adb = _adb

    with patch(f"{DC}.get_channel", return_value=channel):
        xml = asyncio.run(p._dump_ui_xml())

    channel.press.assert_called_once_with("back")
    assert "fullName" in xml and "inputmethod" not in xml


def test_a_stubborn_keyboard_still_yields_an_observation():
    """A poor observation is recoverable; a missing one ends the cycle."""
    p = _pipeline()
    channel = MagicMock()
    channel.dump_hierarchy.side_effect = [_IME_ONLY, _IME_ONLY]
    channel.press.return_value = True

    async def _adb(*args):
        return True, ""

    p._adb = _adb

    with patch(f"{DC}.get_channel", return_value=channel):
        xml = asyncio.run(p._dump_ui_xml())

    assert xml, "must return something rather than None"


def test_adbutils_env_uses_the_names_adbutils_actually_reads(monkeypatch):
    """
    adbutils 2.12 reads ANDROID_ADB_SERVER_HOST, not ADB_SERVER_HOST. Setting
    only the latter looks right, changes nothing, and fails silently: the
    channel degraded to subprocesses for a whole live scan and the
    node-targeted set_text never ran.
    """
    import os
    from sudarshan_core.sandbox.device_channel import _export_adb_server_env

    monkeypatch.setenv("ADB_SERVER_SOCKET", "tcp:host.docker.internal:5037")
    monkeypatch.setenv("RUNNING_IN_DOCKER", "true")
    for var in ("ADB_SERVER_HOST", "ADB_SERVER_PORT",
                "ANDROID_ADB_SERVER_HOST", "ANDROID_ADB_SERVER_PORT"):
        monkeypatch.delenv(var, raising=False)

    _export_adb_server_env()

    assert os.environ["ANDROID_ADB_SERVER_HOST"] == "host.docker.internal"
    assert os.environ["ANDROID_ADB_SERVER_PORT"] == "5037"



# ── field labels on WebView forms ────────────────────────────────────────────

_ECHALLAN_XML = (
    '<?xml version="1.0"?><hierarchy>'
    '<node class="android.widget.TextView" package="com.hsjjsjs.android" '
    'text="Challan Details" bounds="[91,467][987,538]"/>'
    '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
    'resource-id="fullName" text="" hint="Full Name*" clickable="true" '
    'bounds="[91,648][987,777]"/>'
    '<node class="android.view.View" package="com.hsjjsjs.android" '
    'text="Full Name*" bounds="[126,687][357,737]"/>'
    '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
    'resource-id="mb" text="" hint="Mobile Number*" clickable="true" '
    'bounds="[91,813][987,939]"/>'
    '<node class="android.view.View" package="com.hsjjsjs.android" '
    'text="Mobile Number*" bounds="[126,850][451,903]"/>'
    '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
    'resource-id="mt" text="" hint="Mother Name*" clickable="true" '
    'bounds="[91,976][987,1105]"/>'
    '</hierarchy>'
)


def test_webview_placeholders_do_not_shift_field_labels_by_one():
    """
    On a WebView the placeholder is a separate node rendered INSIDE the field's
    bounds and emitted AFTER it, so the caption walk's "the last text I passed
    is this field's caption" inverts.

    Measured on the eChallan payload before this fix: `fullName` was labelled
    "Challan Details" (the card heading), `mb` was labelled "Full Name*" and
    `mt` was labelled "Mobile Number*" - every field wearing the previous
    one's placeholder, and the action against the first box reading
    `type_text "Challan Details"`.
    """
    p = _pipeline()
    by_rid = {
        n.resource_id: n for n in p._parse_ui_nodes(_ECHALLAN_XML) if n.is_input
    }

    assert by_rid["fullName"].field_label == "Full Name*"
    assert by_rid["mb"].field_label == "Mobile Number*"
    assert by_rid["mt"].field_label == "Mother Name*"


def test_fields_without_a_hint_still_use_the_caption_walk():
    """
    Native layouts DO put the caption above the box and expose no hint. The
    walk must keep working there - this fix adds a preference, it does not
    replace the mechanism.
    """
    p = _pipeline()
    xml = (
        '<?xml version="1.0"?><hierarchy>'
        '<node class="android.widget.TextView" package="com.hsjjsjs.android" '
        'text="Username" bounds="[0,0][100,50]"/>'
        '<node class="android.widget.EditText" package="com.hsjjsjs.android" '
        'resource-id="u" text="" clickable="true" bounds="[0,60][100,110]"/>'
        '</hierarchy>'
    )
    inputs = [n for n in p._parse_ui_nodes(xml) if n.is_input]
    assert inputs and inputs[0].field_label == "Username"
