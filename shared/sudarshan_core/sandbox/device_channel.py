"""
One persistent connection per device, shared by perception and input.

WHY THIS EXISTS
───────────────
Every device interaction in the explorer used to go through
`security.adb_gateway.run_adb`, which does `subprocess.run([adb, ...])`. That is
a process spawn plus a TCP connection to the ADB server -- which, under Docker,
lives on the host (ADB_SERVER_SOCKET=tcp:host.docker.internal:5037) -- for EVERY
command.

One observation in PerceptionPipeline costs six of them:

    adb shell uiautomator dump /data/local/tmp/ui_dump.xml
    adb shell cat /data/local/tmp/ui_dump.xml
    adb shell dumpsys activity activities
    adb shell screencap -p ... ; adb pull ... ; adb shell rm ...

and one action costs ten to fifteen once verification re-dumps. Measured on a
real run: 5 actions in 611 seconds -- about two minutes per click, against a
300-second budget. The explorer was not making bad decisions; it never got to
make more than five of them. `coverage_percent` was 0, `forms_completed` was 1.

Subprocess-per-command is the ceiling, and no amount of tuning moves it. This
module replaces it with a single long-lived connection:

    * uiautomator2 runs a server ON the device and holds one connection for the
      whole session. dump_hierarchy() is one call instead of a dump-to-file
      plus a cat.
    * shell() goes over that same connection -- no process spawn, no handshake.
    * click/set_text target a NODE rather than a coordinate.

The last point is a correctness fix, not a speed one. `input tap x y` and
`input text` operate on whatever happens to be on screen and focused. A real
run typed generated credentials into `com.google.android.apps.nexuslauncher`
because the app moved to the background between the observation and the tap.
A node-targeted `set_text` cannot do that: it resolves the field, or it fails
and says so.

DEGRADATION
───────────
`available` is False when uiautomator2 is not installed or cannot reach the
device, and every caller keeps its original ADB path as a fallback. A sandbox
without the on-device agent is slower, exactly as it is today -- never broken.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

#: Opt-out. Set SUDARSHAN_DEVICE_CHANNEL=0 to force every caller back onto the
#: subprocess ADB path -- useful to isolate whether a regression came from this
#: layer without rebuilding the image.
_ENABLED = (os.getenv("SUDARSHAN_DEVICE_CHANNEL", "1").strip().lower()
            not in {"0", "false", "no", "off"})

#: How long to wait for the on-device agent to come up on first connect. u2
#: installs/starts it on demand, which is slow once and fast forever after.
_CONNECT_TIMEOUT = float(os.getenv("SUDARSHAN_DEVICE_CHANNEL_TIMEOUT", "90.0"))


#: The variable names adbutils actually reads, verified against adbutils 2.12
#: (`_adb.py`: `os.environ.get("ANDROID_ADB_SERVER_HOST", "127.0.0.1")`).
#:
#: These are the names Google's own `adb` binary uses, NOT the ADB_SERVER_HOST /
#: ADB_SERVER_PORT pair. Setting only the latter looks right, changes nothing,
#: and fails silently: adbutils keeps its 127.0.0.1 default, `u2.connect()`
#: raises "connect to adb server failed: [Errno 111] Connection refused", and
#: DeviceChannel degrades to the subprocess path for the whole run. That is
#: exactly what happened on a live scan - the node-targeted set_text never ran
#: and typing fell back to `input text`.
_ADBUTILS_HOST_VARS = ("ANDROID_ADB_SERVER_HOST", "ADB_SERVER_HOST")
_ADBUTILS_PORT_VARS = ("ANDROID_ADB_SERVER_PORT", "ADB_SERVER_PORT")


def _export_adb_server_env() -> None:
    """
    Translate ADB_SERVER_SOCKET into the variables adbutils actually reads.

    adbutils (and uiautomator2 above it) speak the ADB wire protocol directly.
    They know nothing about ADB_SERVER_SOCKET, which is an `adb` BINARY flag.
    Without this translation a container configured perfectly for the adb CLI
    has uiautomator2 dialling 127.0.0.1:5037 inside its own namespace, where
    nothing listens.

    Both spellings are exported: ANDROID_* is what adbutils reads today, and
    the unprefixed pair is kept so a future version, or another library, that
    prefers those names still finds them.
    """
    from sudarshan_core.sandbox.config import adb_server_host, adb_server_port

    host = adb_server_host()
    if host:
        for var in _ADBUTILS_HOST_VARS:
            if not os.getenv(var):
                os.environ[var] = host
    port = adb_server_port()
    if port:
        for var in _ADBUTILS_PORT_VARS:
            if not os.getenv(var):
                os.environ[var] = str(port)


class DeviceChannel:
    """
    A persistent device connection. Never raises; failures answer False/None.

    Callers are expected to fall back to their existing ADB path on a falsy
    answer, so a channel that cannot connect degrades the run's throughput
    rather than ending it.
    """

    def __init__(self, serial: str) -> None:
        self.serial = serial
        self._d: Any = None
        self._connect_failed = False
        self._lock = threading.Lock()

    # ── connection ────────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """True when the on-device agent is connected and answering."""
        if not _ENABLED or self._connect_failed:
            return False
        return self._device() is not None

    def _adb_device(self) -> Any:
        return self.serial

    def _device(self) -> Any:
        """Connect once, lazily. A failed connect is remembered, not retried."""
        if self._d is not None:
            return self._d
        if self._connect_failed or not _ENABLED:
            return None
        with self._lock:
            if self._d is not None:
                return self._d
            if self._connect_failed:
                return None
            try:
                _export_adb_server_env()
                import uiautomator2 as u2
            except ImportError:
                logger.warning(
                    "[DeviceChannel] uiautomator2 is not installed - every "
                    "device interaction will spawn an adb subprocess, which "
                    "costs roughly two minutes per explorer action. Install it "
                    "to restore full exploration throughput."
                )
                self._connect_failed = True
                return None
            try:
                device = u2.connect(self._adb_device())
                # Force a round trip: u2.connect() can return an object whose
                # first real call is what actually fails.
                info = device.info
                self._d = device
                logger.info(
                    "[DeviceChannel] Connected to %s (sdk=%s, display=%sx%s) - "
                    "perception and input now share one persistent connection",
                    self.serial,
                    info.get("sdkInt"),
                    info.get("displayWidth"),
                    info.get("displayHeight"),
                )
                return self._d
            except Exception as exc:            # noqa: BLE001
                logger.warning(
                    "[DeviceChannel] Could not connect to %s (%s: %s) - "
                    "falling back to adb subprocesses for this run.",
                    self.serial, type(exc).__name__, exc,
                )
                self._connect_failed = True
                return None

    # ── perception ────────────────────────────────────────────────────────────

    def dump_hierarchy(self) -> Optional[str]:
        """
        The UI hierarchy XML, or None.

        Replaces `uiautomator dump <file>` + `cat <file>`: two subprocess
        spawns, a device-side file write and a read back, per observation.
        """
        device = self._device()
        if device is None:
            return None
        try:
            return device.dump_hierarchy()
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] dump_hierarchy failed: %s", exc)
            return None

    def screenshot(self, path: str) -> bool:
        """Save a screenshot. Replaces screencap + pull + rm (three spawns)."""
        device = self._device()
        if device is None:
            return False
        try:
            device.screenshot(path)
            return os.path.isfile(path)
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] screenshot failed: %s", exc)
            return False

    def foreground_package(self) -> Optional[str]:
        """Current foreground package, without a dumpsys round trip."""
        device = self._device()
        if device is None:
            return None
        try:
            return (device.app_current() or {}).get("package")
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] app_current failed: %s", exc)
            return None

    def current_activity(self) -> Optional[str]:
        """
        Foreground component as ``package/activity``, matching the shape
        `parse_foreground_activity` returns from dumpsys, so callers can treat
        both sources identically.
        """
        device = self._device()
        if device is None:
            return None
        try:
            current = device.app_current() or {}
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] app_current failed: %s", exc)
            return None
        package = (current.get("package") or "").strip()
        activity = (current.get("activity") or "").strip()
        if not package or not activity:
            return None
        return f"{package}/{activity}"

    def window_size(self) -> Optional[Tuple[int, int]]:
        device = self._device()
        if device is None:
            return None
        try:
            w, h = device.window_size()
            return int(w), int(h)
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] window_size failed: %s", exc)
            return None

    # ── input ─────────────────────────────────────────────────────────────────

    def click_xy(self, x: int, y: int) -> bool:
        """
        Tap a coordinate over the persistent connection.

        Still coordinate-based, so it carries the same blindness as
        `input tap` - prefer click_node when a selector is available. What it
        saves is the subprocess.
        """
        device = self._device()
        if device is None:
            return False
        try:
            device.click(x, y)
            return True
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] click_xy failed: %s", exc)
            return False

    def click_node(self, **selector: Any) -> bool:
        """
        Click the node matching `selector` (text=, resourceId=, description=).

        The selector resolves against the live hierarchy and waits for the node
        to exist, so this cannot land on a soft-keyboard key the way a stale
        coordinate can - which is the failure the whole IME-dismissal block in
        ToolExecutor was written to work around.
        """
        device = self._device()
        if device is None:
            return False
        try:
            node = device(**selector)
            if not node.exists:
                return False
            node.click()
            return True
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] click_node(%s) failed: %s", selector, exc)
            return False

    def set_text_node(self, value: str, **selector: Any) -> bool:
        """
        Set a field's text directly, by node.

        This is the correctness fix, not just a speed one. `input text` writes
        to whatever currently holds focus: on a real run that was the launcher,
        because the app had moved to the background between the observation and
        the keystrokes, and the run recorded generated credentials as typed
        into `com.google.android.apps.nexuslauncher`.

        set_text resolves the field first. It also replaces the field contents
        rather than appending, which removes the MOVE_END + N x KEYCODE_DEL
        clearing dance, needs no IME on screen at all, and carries non-ASCII
        that `input text` cannot express.
        """
        device = self._device()
        if device is None:
            return False
        try:
            node = device(**selector)
            if not node.exists:
                return False
            node.set_text(value)
            return True
        except Exception as exc:                # noqa: BLE001
            logger.debug(
                "[DeviceChannel] set_text_node(%s) failed: %s", selector, exc,
            )
            return False

    def set_text_focused(self, value: str) -> bool:
        """Set the focused field's text. Fallback when no selector is known."""
        return self.set_text_node(value, focused=True)

    def press(self, key: str) -> bool:
        device = self._device()
        if device is None:
            return False
        try:
            device.press(key)
            return True
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] press(%s) failed: %s", key, exc)
            return False

    # ── shell ─────────────────────────────────────────────────────────────────

    def shell(self, command: str, timeout: float = 30.0) -> Optional[Tuple[bool, str]]:
        """
        Run a shell command over the persistent connection.

        Returns None when the channel is unavailable, so the caller can tell
        "no channel" (fall back to adb) from "ran and failed" (False, output).

        NOTE: the on-device agent does not report real exit codes - it answers
        0 or 1 - so success here means "the command ran", not "the command
        succeeded" with the fidelity `adb shell` gives. Callers that branch on
        an exact exit status must keep using the ADB path.
        """
        device = self._device()
        if device is None:
            return None
        try:
            result = device.shell(command, timeout=timeout)
            output = getattr(result, "output", None)
            if output is None:
                output = result if isinstance(result, str) else str(result)
            code = getattr(result, "exit_code", 0)
            return (code == 0), (output or "").strip()
        except Exception as exc:                # noqa: BLE001
            logger.debug("[DeviceChannel] shell(%r) failed: %s", command, exc)
            return None

    def close(self) -> None:
        self._d = None


# ── registry ──────────────────────────────────────────────────────────────────

_channels: Dict[str, DeviceChannel] = {}
_registry_lock = threading.Lock()


def get_channel(serial: str) -> DeviceChannel:
    """
    The channel for `serial`, creating it on first use.

    Cached per serial for the life of the process: the point of the channel is
    that the connection outlives individual commands, so building a new one per
    caller would reintroduce exactly the cost it removes.
    """
    with _registry_lock:
        channel = _channels.get(serial)
        if channel is None:
            channel = DeviceChannel(serial)
            _channels[serial] = channel
        return channel


def close_all() -> None:
    """Drop every cached channel. Used between runs and in tests."""
    with _registry_lock:
        for channel in _channels.values():
            channel.close()
        _channels.clear()
