"""
SUDARSHAN — Device Properties Provider
========================================
THE single source of truth for physical device characteristics.

Why this module exists
----------------------
Screen dimensions were previously defined in two places that disagreed:

  * ``tool_executor``  read ``SUDARSHAN_SCREEN_WIDTH/HEIGHT`` from the
    environment, defaulting to 1080x1920.
  * ``tool_registry``  hardcoded ``DEFAULT_SCREEN_WIDTH/HEIGHT`` = 1080x1920,
    and the planner validated LLM coordinates against those constants — with a
    comment claiming an environment override that was never implemented there.

On the project's own Pixel_6 AVD (1080x2400) that mismatch rejected EVERY action
targeting the bottom 480 pixels — 20% of the screen — as ``Step5_OutOfBounds``,
burning an LLM retry and then forcing the FallbackPlanner. Setting the
environment variable could not fix it, because the validator never read it.

Resolution order (first hit wins):
  1. ``SUDARSHAN_SCREEN_WIDTH`` / ``SUDARSHAN_SCREEN_HEIGHT`` — explicit operator override
  2. ``adb shell wm size``                                    — the real device
  3. ``FALLBACK_SCREEN_WIDTH`` / ``FALLBACK_SCREEN_HEIGHT``   — last resort

The device is queried at most once per (adb_path, serial) and cached, because
resolution does not change mid-analysis and ADB round-trips are expensive.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Used only when neither an override nor the device can supply a value.
FALLBACK_SCREEN_WIDTH: int = 1080
FALLBACK_SCREEN_HEIGHT: int = 1920

# Guard against a malformed `wm size` producing absurd bounds.
_MIN_DIMENSION: int = 240
_MAX_DIMENSION: int = 8192

# `wm size` prints "Physical size: 1080x2400" and, when overridden,
# additionally "Override size: 720x1600". The override is what is actually
# rendered, so it wins when present.
_PHYSICAL_RE = re.compile(r"Physical size:\s*(\d+)x(\d+)")
_OVERRIDE_RE = re.compile(r"Override size:\s*(\d+)x(\d+)")

_cache: Dict[Tuple[str, str], Tuple[int, int]] = {}
_cache_lock = threading.Lock()


def _env_override() -> Optional[Tuple[int, int]]:
    """Return an operator-supplied resolution, if both values are valid."""
    raw_w = os.getenv("SUDARSHAN_SCREEN_WIDTH")
    raw_h = os.getenv("SUDARSHAN_SCREEN_HEIGHT")
    if not raw_w or not raw_h:
        return None
    try:
        width, height = int(raw_w), int(raw_h)
    except ValueError:
        logger.warning(
            f"[DeviceProps] Ignoring non-numeric screen override "
            f"({raw_w!r}x{raw_h!r})"
        )
        return None
    if not _plausible(width, height):
        logger.warning(f"[DeviceProps] Ignoring implausible override {width}x{height}")
        return None
    return width, height


def _plausible(width: int, height: int) -> bool:
    return (
        _MIN_DIMENSION <= width <= _MAX_DIMENSION
        and _MIN_DIMENSION <= height <= _MAX_DIMENSION
    )


def parse_wm_size(output: str) -> Optional[Tuple[int, int]]:
    """
    Parse `adb shell wm size` output into (width, height).

    Pure function so every branch is unit-testable without a device.
    Returns None when no plausible size is present.
    """
    if not output:
        return None
    # An override size is what the display actually renders at.
    for pattern in (_OVERRIDE_RE, _PHYSICAL_RE):
        match = pattern.search(output)
        if match:
            width, height = int(match.group(1)), int(match.group(2))
            if _plausible(width, height):
                return width, height
            logger.warning(f"[DeviceProps] Implausible wm size {width}x{height} ignored")
    return None


def get_screen_size(
    adb_path: str = "adb",
    device_serial: str = "",
    use_cache: bool = True,
) -> Tuple[int, int]:
    """
    Return (width, height) for the target device.

    Never raises and never blocks indefinitely: on any failure it degrades to
    the fallback constants, because a wrong-but-sane resolution is far better
    than aborting an analysis.
    """
    override = _env_override()
    if override:
        return override

    key = (adb_path or "adb", device_serial or "")
    if use_cache:
        with _cache_lock:
            if key in _cache:
                return _cache[key]

    size: Optional[Tuple[int, int]] = None
    try:
        cmd = [adb_path or "adb"]
        if device_serial:
            cmd += ["-s", device_serial]
        cmd += ["shell", "wm", "size"]
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        size = parse_wm_size(completed.stdout or "")
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning(
            f"[DeviceProps] Could not query device resolution "
            f"({type(exc).__name__}: {exc}) — using "
            f"{FALLBACK_SCREEN_WIDTH}x{FALLBACK_SCREEN_HEIGHT}"
        )

    if size is None:
        size = (FALLBACK_SCREEN_WIDTH, FALLBACK_SCREEN_HEIGHT)
    else:
        logger.info(f"[DeviceProps] Device resolution: {size[0]}x{size[1]}")

    if use_cache:
        with _cache_lock:
            _cache[key] = size
    return size


def clear_cache() -> None:
    """Drop cached resolutions. Used by tests and on device reconnection."""
    with _cache_lock:
        _cache.clear()
